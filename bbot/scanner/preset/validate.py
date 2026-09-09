"""
Public `validate_preset()` API for BBOT presets.

Given a preset-as-dict (i.e. what comes out of a YAML file before it's
instantiated), return a list of human-readable errors.

The validator does a single pass against a composite pydantic schema
(built once per module-loader state by `ModuleLoader.validation_schema`)
that covers every layer in one tree:

- top-level preset keys (e.g. `modlues:` typo)
- global config (e.g. `scope.strct`, `web.http_timoeut`)
- unknown module names (e.g. `modules.nucleii`)
- per-module config (e.g. `modules.nuclei.tgas`)

Errors are aggregated so a user with multiple typos sees them all. The
caller decides whether to raise or just print them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from bbot.errors import BBOTError
from bbot.core.config.models import PresetSchema
from bbot.core.helpers.misc import get_closest_match


def _preset_top_level_keys() -> set[str]:
    """Field names and aliases declared on PresetSchema, used for closest-match
    suggestions on unknown top-level preset keys (e.g. `modlues` -> `modules`)."""
    keys: set[str] = set()
    for name, field in PresetSchema.model_fields.items():
        keys.add(name)
        alias = getattr(field, "alias", None)
        if alias:
            keys.add(alias)
    return keys


_PRESET_KEYS = _preset_top_level_keys()


log = logging.getLogger("bbot.presets.validate")


@dataclass
class PresetValidationError:
    """A single validation problem. Stringifies to a human-readable message."""

    where: str  # "preset", "config", "module:<name>"
    path: str  # dotted location, e.g. "scope.strict" or ""
    message: str

    def __str__(self) -> str:
        loc = f"{self.where}:{self.path}" if self.path else self.where
        return f"[{loc}] {self.message}"


def _classify_loc(loc: tuple) -> tuple[str, str]:
    """
    Map a pydantic error path to a (where, path) pair.

    Examples:
        ('modlues',)                              -> ('preset', 'modlues')
        ('config', 'scope', 'strct')              -> ('config', 'scope.strct')
        ('config', 'modules', 'nucleii')          -> ('preset', 'config.modules.nucleii')
        ('config', 'modules', 'nuclei', 'tgas')   -> ('module:nuclei', 'tgas')
    """
    parts = [str(p) for p in loc]

    if len(parts) >= 2 and parts[0] == "config" and parts[1] == "modules":
        # Error is somewhere under config.modules.*
        if len(parts) == 2:
            # The `modules` mapping itself has the wrong shape (e.g. a list).
            # Classify as a config-level error rather than walking deeper.
            return ("config", "modules")
        if len(parts) == 3:
            # The module name itself is unknown (extra_forbidden on ModulesSchema)
            return ("preset", ".".join(parts))
        # Error is within a known module's config
        module_name = parts[2]
        return (f"module:{module_name}", ".".join(parts[3:]))

    if parts and parts[0] == "config":
        return ("config", ".".join(parts[1:]))

    return ("preset", ".".join(parts))


def _format_msg(err: dict, known_modules: set | None = None, known_paths: set | None = None) -> str:
    kind = err["type"]
    input_value = err.get("input")
    loc = err["loc"]
    field = str(loc[-1]) if loc else ""
    path = ".".join(str(p) for p in loc)

    if kind == "extra_forbidden":
        # Special-case unknown module name (config.modules.<bad>) — users get
        # a suggestion drawn from the set of known module names.
        if len(loc) == 3 and loc[0] == "config" and loc[1] == "modules":
            return get_closest_match(field, known_modules or set(), msg="module")
        # Top-level preset key (e.g. `modlues:`) — suggest from PresetSchema
        # field names rather than the dotted config-path universe, so users
        # get useful hints like "Did you mean 'modules'?".
        if len(loc) == 1:
            return get_closest_match(field, _PRESET_KEYS, msg="preset option")
        # For everything else, suggest from the known dotted-path universe
        # (`web.spier_distance` → `web.spider_distance`).
        if known_paths:
            # strip the leading "config." prefix when matching, since
            # default_config dotted paths don't include it
            lookup_path = ".".join(str(p) for p in loc[1:]) if loc and loc[0] == "config" else path
            return get_closest_match(lookup_path, known_paths, msg="config option")
        msg = f"Unknown option: {field!r}"
        if isinstance(input_value, (str, int, bool, float)):
            msg += f" (value: {input_value!r})"
        elif isinstance(input_value, list) and len(input_value) <= 5:
            msg += f" (value: {input_value!r})"
        return msg

    if kind in {"int_parsing", "int_type"}:
        return f"Expected an integer, got {type(input_value).__name__}: {input_value!r}"
    if kind in {"bool_parsing", "bool_type"}:
        return f"Expected a boolean, got {type(input_value).__name__}: {input_value!r}"
    if kind == "string_type":
        return f"Expected a string, got {type(input_value).__name__}: {input_value!r}"
    if kind == "list_type":
        return f"Expected a list, got {type(input_value).__name__}"
    if kind == "dict_type":
        return f"Expected a mapping, got {type(input_value).__name__}"
    if kind == "literal_error":
        # pydantic stashes the allowed values in ctx["expected"] formatted like:
        # "'manual', 'technology', 'severe' or 'budget'"
        ctx = err.get("ctx") or {}
        expected = ctx.get("expected", "")
        return f"Expected one of {expected}, got {input_value!r}" if expected else err.get("msg", "")
    if kind == "missing":
        return f"Required option {field!r} is missing"
    if kind == "value_error":
        # Pydantic wraps ValueError raised inside a field_validator and prefixes
        # the message with "Value error, ". Surface the original ValueError text
        # so the error reads naturally.
        ctx = err.get("ctx") or {}
        inner = ctx.get("error")
        if inner is not None:
            return str(inner)
        msg = err.get("msg", "")
        prefix = "Value error, "
        return msg[len(prefix) :] if msg.startswith(prefix) else msg

    # Fallback to pydantic's own message
    return err["msg"] if err.get("msg") else f"validation error at {path}"


def _format_errors(
    exc: ValidationError,
    known_modules: set | None = None,
    known_paths: set | None = None,
) -> list[PresetValidationError]:
    out: list[PresetValidationError] = []
    for err in exc.errors():
        where, path = _classify_loc(err["loc"])
        out.append(PresetValidationError(where=where, path=path, message=_format_msg(err, known_modules, known_paths)))
    return out


def prevalidate_preset(preset_dict: Any) -> list[PresetValidationError]:
    """Validate a preset's top-level KEY names only -- the gate `Preset.from_dict`
    runs up front. Reports every unknown/typo'd key with a closest-match hint;
    config VALUES are validated later by `Preset.validate()`, not here.

    Examples:
        >>> print(prevalidate_preset({"modlues": ["nuclei"]})[0])
        [preset:modlues] Could not find preset option "modlues". Did you mean "modules"?
    """
    if not isinstance(preset_dict, dict):
        return [PresetValidationError("preset", "", f"Expected a mapping, got {type(preset_dict).__name__}")]
    errors: list[PresetValidationError] = []
    for key in preset_dict:
        if key not in _PRESET_KEYS:
            errors.append(
                PresetValidationError(
                    "preset", str(key), get_closest_match(str(key), _PRESET_KEYS, msg="preset option")
                )
            )
    return errors


def validate_preset(preset_dict: Any, module_loader=None) -> list[PresetValidationError]:
    """
    Validate a preset dict against BBOT's composite schema.

    Returns a list of `PresetValidationError` objects. An empty list means
    the preset is valid. Errors from all layers are aggregated, so a user
    with multiple typos sees them all at once.

    **Side effect**: any custom `module_dirs` declared in the preset (either
    at top level or inside `config`) are registered with `module_loader` so
    their modules become known. Without this, modules from a custom dir
    would be falsely reported as unknown. Idempotent — `add_module_dir`
    short-circuits on already-loaded directories.

    Args:
        preset_dict: Preset as a plain dict (e.g. from `yaml.safe_load`).
        module_loader: Optional module loader. Falls back to the global
            `MODULE_LOADER` if not provided.

    Examples:
        >>> errors = validate_preset({"modlues": ["nuclei"]})
        >>> print(errors[0])
        [preset:modlues] Unknown option: 'modlues' (value: ['nuclei'])
    """
    if not isinstance(preset_dict, dict):
        return [PresetValidationError("preset", "", f"Expected a dict, got {type(preset_dict).__name__}")]

    if module_loader is None:
        from bbot.core.modules import MODULE_LOADER

        module_loader = MODULE_LOADER

    errors: list[PresetValidationError] = []

    # Pre-load any custom module_dirs the preset declares so the composite
    # schema includes their modules. Defensive iteration — bad shape gets
    # surfaced by the schema pass below.
    config_dict = preset_dict.get("config")
    for source in (
        preset_dict.get("module_dirs"),
        config_dict.get("module_dirs") if isinstance(config_dict, dict) else None,
    ):
        # Skip non-list shapes (e.g. a string) so we don't iterate characters
        # and trigger filesystem calls. The schema pass below reports the
        # actual type error.
        if not isinstance(source, list):
            continue
        for d in source:
            if not isinstance(d, str):
                continue
            # A bad custom module (e.g. a legacy options dict, which preload rejects
            # via sys.exit) must not kill a caller that just wants a list of errors.
            try:
                module_loader.add_module_dir(d)
            except (SystemExit, Exception) as e:
                detail = str(e).strip()
                suffix = f": {detail}" if detail and detail != "1" else ""
                errors.append(
                    PresetValidationError("preset", "module_dirs", f"Failed to load module dir {d!r}{suffix}")
                )

    known_modules = set(module_loader.all_module_choices)
    # The type index is the single source of truth for known dotted config
    # paths -- both for coercion AND for "did you mean ...?" suggestions.
    known_paths = set(module_loader.config_type_index)

    # Validate against the composite schema (rebuilt automatically if new
    # module_dirs were just preloaded above). Closest-match suggestions
    # for unknown module names + config options are produced inside the formatter.
    try:
        module_loader.validation_schema.model_validate(preset_dict)
    except ValidationError as e:
        errors.extend(_format_errors(e, known_modules=known_modules, known_paths=known_paths))
    except BBOTError as e:
        # A custom module with an invalid `class Config` raises when the schema is
        # built/exec'd. Report it instead of letting it propagate out of this API.
        errors.append(PresetValidationError("preset", "", str(e)))

    # Module names listed in top-level `modules`/`output_modules`/`exclude_modules`
    # aren't covered by the composite schema (they're a list of strings, not a
    # nested mapping). Check them explicitly, with the same closest-match hint.
    # Skip non-list values; the schema pass above already flagged the type error,
    # and iterating a string here would yield bogus per-character lookups.
    for key in ("modules", "output_modules", "exclude_modules", "exclude_output_modules"):
        value = preset_dict.get(key)
        if not isinstance(value, list):
            continue
        for name in value:
            # non-string entries (e.g. a dangling YAML item -> None) already get a
            # type error from the schema pass; skip so get_closest_match's difflib doesn't choke
            if not isinstance(name, str):
                continue
            if name not in known_modules:
                hint = get_closest_match(name, known_modules, msg="module")
                errors.append(PresetValidationError(where="preset", path=key, message=hint))

    return errors


def validate_preset_file(path: str | Path, **kwargs) -> list[PresetValidationError]:
    """Convenience wrapper for validating a YAML preset file on disk.

    Returns a list of errors. A missing file or unreadable YAML is reported
    as a single error rather than raised, so callers can treat all failure
    modes uniformly.
    """
    import yaml

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return [PresetValidationError("preset", "", f"Preset file not found: {path}")]
    except OSError as e:
        return [PresetValidationError("preset", "", f"Could not read preset file {path}: {e}")]
    except yaml.YAMLError as e:
        return [PresetValidationError("preset", "", f"Invalid YAML in {path}: {e}")]
    if not isinstance(data, dict):
        return [PresetValidationError("preset", "", f"Expected a YAML mapping, got {type(data).__name__}")]
    return validate_preset(data, **kwargs)


__all__ = ["PresetValidationError", "prevalidate_preset", "validate_preset", "validate_preset_file"]
