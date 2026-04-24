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

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


STRICT = ConfigDict(extra="forbid")


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


class WebConfig(BaseModel):
    model_config = STRICT

    http_proxy: Optional[str] = None
    user_agent: Optional[str] = None
    user_agent_suffix: Optional[str] = None
    spider_distance: Optional[int] = None
    spider_depth: Optional[int] = None
    spider_links_per_page: Optional[int] = None
    http_timeout: Optional[int] = None
    httpx_timeout: Optional[int] = None
    http_headers: Optional[dict[str, str]] = None
    http_cookies: Optional[dict[str, str]] = None
    api_retries: Optional[int] = None
    http_retries: Optional[int] = None
    httpx_retries: Optional[int] = None
    # The `429_*` keys start with a digit, so we expose them via aliases.
    sleep_interval_429: Optional[int] = Field(default=None, alias="429_sleep_interval")
    max_sleep_interval_429: Optional[int] = Field(default=None, alias="429_max_sleep_interval")
    debug: Optional[bool] = None
    http_max_redirects: Optional[int] = None
    ssl_verify: Optional[bool] = None


class EngineConfig(BaseModel):
    model_config = STRICT

    debug: Optional[bool] = None


class DepsToolConfig(BaseModel):
    """Per-tool dep config (e.g. `deps.ffuf.version`)."""

    model_config = STRICT

    version: Optional[str] = None


class DepsConfig(BaseModel):
    model_config = STRICT

    behavior: Optional[str] = None
    ffuf: Optional[DepsToolConfig] = None


class BaseModuleConfig(BaseModel):
    """
    Shared base for every module's `class Config(BaseModuleConfig)`.

    Declares the three universal module options that are applied to every
    module regardless of declaration. The actual default values live in
    `bbot/defaults.yml`; this class only validates shape.
    """

    model_config = STRICT

    batch_size: Optional[int] = None
    module_threads: Optional[int] = None
    module_timeout: Optional[int] = None


class BBOTConfig(BaseSettings):
    """
    Root BBOT config schema. Unknown top-level keys are rejected so that
    typos like `scpoe:` or `moudules:` become loud errors instead of silent
    no-ops.

    This is a validation schema only — it has no default values. The real
    defaults live in `bbot/defaults.yml`.
    """

    model_config = SettingsConfigDict(
        extra="forbid",
        env_prefix="BBOT_",
        env_nested_delimiter="__",
        populate_by_name=True,
    )

    # Basic options
    home: Optional[str] = None
    keep_scans: Optional[int] = None
    status_frequency: Optional[int] = None
    file_blobs: Optional[bool] = None
    folder_blobs: Optional[bool] = None

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
    interactsh_token: Optional[str] = None
    interactsh_disable: Optional[bool] = None

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
    "DepsConfig",
    "DepsToolConfig",
    "DnsConfig",
    "EngineConfig",
    "PresetSchema",
    "ScopeConfig",
    "WebConfig",
]
