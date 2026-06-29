"""
Pydantic schema for BBOT's global config and preset files.

These models describe the *shape* of valid BBOT configuration — field names
and their expected types — so that `validate_preset()` can catch typos
(`scpoe:`, `http_timoeut:`) and type errors at the boundary.

Defaults live in `bbot/defaults.yml` — the single source of truth. This file
intentionally does **not** repeat those values; every field is optional, and
an absent field passes validation. At runtime, `BBOTConfigFiles` loads the
merged dict straight from YAML, and these models only ever validate shape.
"""

from __future__ import annotations

import os
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, field_validator
from pydantic import Field as _PydanticField
from pydantic_core import PydanticUndefined

from bbot.core.helpers.validators import validate_fqdn_or_ip


STRICT = ConfigDict(extra="forbid")


def _normalize_upper(v):
    """Uppercase a string so severity/confidence options are case-insensitive."""
    return v.upper() if isinstance(v, str) else v


# Single source of truth for severity/confidence option types (used by the baddns family).
# The BeforeValidator normalizes case at validation time so e.g. "low" validates as "LOW".
SeverityLiteral = Annotated[Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], BeforeValidator(_normalize_upper)]
ConfidenceLiteral = Annotated[
    Literal["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CONFIRMED"], BeforeValidator(_normalize_upper)
]


def Field(default=PydanticUndefined, *, sensitive: bool = False, mandatory: bool = False, **kwargs):
    """
    Drop-in replacement for `pydantic.Field` that records two BBOT-specific
    flags as field metadata:

    - `sensitive=True`: value should be redacted when serializing configs
      (api keys, passwords, http cookies, …).
    - `mandatory=True`: option must be supplied for the module to function;
      drives the "Needs API Key" column in `bbot -l` and the
      `BaseModule.auth_required` property.

    Both flags are stashed under `json_schema_extra` so pydantic preserves
    them on `FieldInfo.json_schema_extra` (and in any generated JSON schema)
    without affecting validation. All other arguments pass through unchanged.
    """
    extra = dict(kwargs.pop("json_schema_extra", None) or {})
    if sensitive:
        extra["sensitive"] = True
    if mandatory:
        extra["mandatory"] = True
    if extra:
        kwargs["json_schema_extra"] = extra
    return _PydanticField(default, **kwargs)


def field_flags(field) -> dict:
    """Return the BBOT flags dict for a pydantic FieldInfo (empty if none)."""
    extra = getattr(field, "json_schema_extra", None)
    return dict(extra) if isinstance(extra, dict) else {}


def is_sensitive(field) -> bool:
    return bool(field_flags(field).get("sensitive"))


def is_mandatory(field) -> bool:
    return bool(field_flags(field).get("mandatory"))


def _unwrap_optional(annotation):
    """Strip a single `Optional[X]` / `Union[X, None]` wrapper, return X. Pass-through otherwise."""
    import typing

    origin = typing.get_origin(annotation)
    if origin is typing.Union:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _resolve_field(model, key):
    """Resolve `key` against `model.model_fields`, honoring `Field(alias=...)`."""
    fields = getattr(model, "model_fields", None)
    if not fields:
        return None
    if key in fields:
        return fields[key]
    for f in fields.values():
        if getattr(f, "alias", None) == key:
            return f
    return None


def _field_submodel(field):
    """If `field`'s annotation is a `BaseModel` subclass, return it; else None."""
    if field is None:
        return None
    ann = _unwrap_optional(field.annotation)
    if isinstance(ann, type) and issubclass(ann, BaseModel):
        return ann
    return None


def _yaml_scalar(value):
    """yaml.safe_load a raw string, but never coerce to date/time. Non-strings pass through."""
    import datetime as _dt
    import yaml as _yaml

    if not isinstance(value, str):
        return value
    if value == "":
        return ""
    try:
        parsed = _yaml.safe_load(value)
    except _yaml.YAMLError:
        return value
    return value if isinstance(parsed, (_dt.date, _dt.time)) else parsed


def coerce_value(value, adapter):
    """Coerce one config value toward its declared type via a pydantic TypeAdapter.

    `value` may be a raw CLI string OR an already-parsed YAML value. `adapter` is
    the field's TypeAdapter (from the config type index), or None when the field is
    unknown -- then fall back to YAML scalar parsing; unknown keys are still caught
    by validation. Returns `value` unchanged if it can't be validated as the declared
    type, so the schema pass reports the real error instead of coercion hiding it.
    """
    from pydantic import ValidationError

    # pydantic won't coerce os.PathLike -> str, so do it up front.
    if isinstance(value, os.PathLike):
        value = str(value)

    if adapter is None:
        return _yaml_scalar(value) if isinstance(value, str) else value

    if isinstance(value, str):
        parsed = _yaml_scalar(value)
        # Keep the raw string for scalar fields (lossless: "1.10", "0755", dates,
        # bad YAML); only the parsed form can satisfy a list/dict-typed field.
        primary = parsed if isinstance(parsed, (list, dict)) else value
        fallback = parsed if primary is value else value
        for candidate in (primary, fallback):
            try:
                return adapter.validate_python(candidate)
            except ValidationError:
                pass
        return value

    try:
        return adapter.validate_python(value)
    except ValidationError:
        return value


def coerce_config(config, index, prefix=""):
    """Walk a config dict and coerce each leaf toward its declared type."""
    out = {}
    for k, v in config.items():
        dotted = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out[k] = coerce_config(v, index, dotted)
        else:
            out[k] = coerce_value(v, index.get(dotted))
    return out


def partition_sensitive_config(config, model, *, keep_sensitive: bool):
    """
    Walk `config` (a dict) alongside the pydantic `model`, returning a copy
    that either drops or extracts every `sensitive=True` field.

    - `keep_sensitive=False` -> caller wants the public, non-secret view (used
      by `BBOTCore.no_secrets_config`).
    - `keep_sensitive=True` -> caller wants only the secrets (used by
      `BBOTCore.secrets_only_config` to materialize `~/.config/bbot/secrets.yml`).

    Unknown keys (no matching field in the schema) pass through unchanged when
    redacting and are dropped when extracting secrets-only.
    """
    import copy as _copy

    if not isinstance(config, dict) or model is None:
        return _copy.deepcopy(config) if keep_sensitive is False else {}

    out: dict = {}
    for key, val in config.items():
        field = _resolve_field(model, key)
        sub_model = _field_submodel(field)

        if sub_model is not None and isinstance(val, dict):
            child = partition_sensitive_config(val, sub_model, keep_sensitive=keep_sensitive)
            # When redacting, preserve the parent key even if its body was
            # entirely sensitive — matches the prior `clean_dict` behavior.
            # When extracting secrets-only, drop empty branches so the result
            # is just the secrets that exist.
            if keep_sensitive:
                if child:
                    out[key] = child
            else:
                out[key] = child
            continue

        if field is None:
            # No matching schema field — pass through unchanged when redacting,
            # drop when extracting secrets-only.
            if not keep_sensitive:
                out[key] = _copy.deepcopy(val)
            continue

        sensitive = is_sensitive(field)
        if keep_sensitive:
            if sensitive:
                out[key] = _copy.deepcopy(val)
        else:
            if not sensitive:
                out[key] = _copy.deepcopy(val)
    return out


class ScopeConfig(BaseModel):
    model_config = STRICT

    strict: Optional[bool] = None
    report_distance: Optional[int] = None
    search_distance: Optional[int] = None


class DnsConfig(BaseModel):
    model_config = STRICT

    disable: Optional[bool] = None
    minimal: Optional[bool] = None
    threads: Optional[int] = None
    cache_size: Optional[int] = None
    brute_threads: Optional[int] = None
    brute_nameservers: Optional[str] = None
    search_distance: Optional[int] = None
    runaway_limit: Optional[int] = None
    timeout: Optional[int] = None
    retries: Optional[int] = None
    wildcard_disable: Optional[bool] = None
    wildcard_ignore: Optional[list[str]] = None
    wildcard_tests: Optional[int] = None
    abort_threshold: Optional[int] = None
    filter_ptrs: Optional[bool] = None
    debug: Optional[bool] = None
    omit_queries: Optional[list[str]] = None


class BodySpillConfig(BaseModel):
    """`web.body_spill` — keeps large HTTP_RESPONSE bodies off the Python heap."""

    model_config = STRICT

    enabled: Optional[bool] = None
    cache_mb: Optional[int] = None
    compress: Optional[bool] = None


class WebConfig(BaseModel):
    model_config = STRICT

    http_proxy: Optional[str] = None
    http_proxy_exclude: Optional[list[str]] = None
    user_agent: Optional[str] = None
    user_agent_suffix: Optional[str] = None
    spider_distance: Optional[int] = None
    spider_depth: Optional[int] = None
    spider_links_per_page: Optional[int] = None
    http_timeout: Optional[int] = None
    http_timeout_infrastructure: Optional[int] = None
    http_headers: Optional[dict[str, str]] = None
    http_cookies: Optional[dict[str, str]] = Field(default=None, sensitive=True)
    api_retries: Optional[int] = None
    http_retries: Optional[int] = None
    http_rate_limit: Optional[int] = None
    body_spill: Optional[BodySpillConfig] = None
    # The `429_*` keys start with a digit, so we expose them via aliases.
    sleep_interval_429: Optional[int] = Field(default=None, alias="429_sleep_interval")
    max_sleep_interval_429: Optional[int] = Field(default=None, alias="429_max_sleep_interval")
    debug: Optional[bool] = None
    http_max_redirects: Optional[int] = None
    ssl_verify_target: Optional[bool] = None
    ssl_verify_infrastructure: Optional[bool] = None


class EngineConfig(BaseModel):
    model_config = STRICT

    debug: Optional[bool] = None


class DepsToolConfig(BaseModel):
    """Per-tool dep config (e.g. `deps.ffuf.version`)."""

    model_config = STRICT

    version: Optional[str] = None


class DepsConfig(BaseModel):
    model_config = STRICT

    behavior: Optional[Literal["abort_on_failure", "retry_failed", "ignore_failed", "disable", "force_install"]] = None
    ffuf: Optional[DepsToolConfig] = None


class BaseModuleConfig(BaseModel):
    """
    Shared base for every module's `class Config(BaseModuleConfig)`.

    Declares the three universal module options that are applied to every
    module regardless of declaration. The actual default values live in
    `bbot/defaults.yml`; this class only validates shape.
    """

    model_config = STRICT

    batch_size: Optional[int] = Field(
        default=None,
        description="The number of events to process in a single batch (only applies to batch modules)",
    )
    module_threads: Optional[int] = Field(
        default=None,
        description="How many event handlers to run in parallel",
    )
    module_timeout: Optional[int] = Field(
        default=None,
        description="Max time in seconds to spend handling each event or batch of events",
    )


class BBOTConfig(BaseModel):
    """
    Root BBOT config schema. Unknown top-level keys are rejected so that
    typos like `scpoe:` or `moudules:` become loud errors instead of silent
    no-ops.

    This is a validation schema only -- it has no default values. The real
    defaults live in `bbot/defaults.yml`.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    # Basic options
    home: Optional[str] = None
    keep_scans: Optional[int] = None
    status_frequency: Optional[int] = None
    redact_secrets: Optional[bool] = None
    file_blobs: Optional[bool] = None
    folder_blobs: Optional[bool] = None
    max_mem_percent: Optional[int] = None

    # Nested sections
    scope: Optional[ScopeConfig] = None
    dns: Optional[DnsConfig] = None
    web: Optional[WebConfig] = None
    engine: Optional[EngineConfig] = None
    deps: Optional[DepsConfig] = None

    # Module loader paths
    module_dirs: Optional[list[str]] = None

    # Module runtime
    module_handle_event_timeout: Optional[int] = None
    module_handle_batch_timeout: Optional[int] = None

    # Internal module toggles (hardcoded because they're first-class scan
    # pipeline features; the set changes rarely)
    speculate: Optional[bool] = None
    excavate: Optional[bool] = None
    aggregate: Optional[bool] = None
    dnsresolve: Optional[bool] = None
    cloudcheck: Optional[bool] = None
    unarchive: Optional[bool] = None
    python: Optional[bool] = None

    # URL handling
    url_querystring_remove: Optional[bool] = None
    url_querystring_collapse: Optional[bool] = None
    url_extension_blacklist: Optional[list[str]] = None
    url_extension_special: Optional[list[str]] = None
    url_extension_static: Optional[list[str]] = None

    # Parameter handling
    parameter_blacklist: Optional[list[str]] = None
    parameter_blacklist_prefixes: Optional[list[str]] = None

    # Event output filter
    omit_event_types: Optional[list[str]] = None

    # Interactsh
    interactsh_server: Optional[str] = None
    interactsh_token: Optional[str] = Field(default=None, sensitive=True)
    interactsh_disable: Optional[bool] = None

    # bbot.io API key (used by the asn helper)
    bbot_io_api_key: Optional[str] = Field(default=None, sensitive=True)

    _validate_interactsh_server = field_validator("interactsh_server")(validate_fqdn_or_ip)

    # Per-module configs — validated separately, per-module, against each
    # module's own `class Config(BaseModuleConfig)`.
    modules: Optional[dict[str, dict[str, Any]]] = None


class PresetSchema(BaseModel):
    """
    Schema for the top-level keys in a preset YAML file. Catches typos like
    `modlues:` or `flgas:` at load time.

    `target`/`targets` and `include`/`presets` are aliases; both are accepted.
    The `config` key is validated separately as `BBOTConfig`.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
    )

    target: Optional[list[str]] = None
    targets: Optional[list[str]] = None
    seeds: Optional[list[str]] = None
    blacklist: Optional[list[str]] = None

    modules: Optional[list[str]] = None
    output_modules: Optional[list[str]] = None
    exclude_modules: Optional[list[str]] = None
    exclude_output_modules: Optional[list[str]] = None
    flags: Optional[list[str]] = None
    require_flags: Optional[list[str]] = None
    exclude_flags: Optional[list[str]] = None

    config: Optional[dict[str, Any]] = None
    module_dirs: Optional[list[str]] = None

    include: Optional[list[str]] = None
    presets: Optional[list[str]] = None

    scan_name: Optional[str] = None
    output_dir: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None

    conditions: Optional[list[str]] = None

    verbose: Optional[bool] = None
    debug: Optional[bool] = None
    silent: Optional[bool] = None


__all__ = [
    "BBOTConfig",
    "BaseModuleConfig",
    "ConfidenceLiteral",
    "DepsConfig",
    "DepsToolConfig",
    "DnsConfig",
    "EngineConfig",
    "Field",
    "PresetSchema",
    "ScopeConfig",
    "SeverityLiteral",
    "WebConfig",
    "coerce_config",
    "coerce_value",
    "field_flags",
    "is_mandatory",
    "is_sensitive",
    "partition_sensitive_config",
]
