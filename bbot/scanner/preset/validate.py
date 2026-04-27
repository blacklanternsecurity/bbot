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
        if len(parts) == 3:
            # The module name itself is unknown (extra_forbidden on ModulesSchema)
            return ("preset", ".".join(parts))
        # Error is within a known module's config
        module_name = parts[2]
        return (f"module:{module_name}", ".".join(parts[3:]))

    if parts and parts[0] == "config":
        return ("config", ".".join(parts[1:]))

    return ("preset", ".".join(parts))


def _format_msg(err: dict) -> str:
    kind = err["type"]
    input_value = err.get("input")
    loc = err["loc"]
    field = str(loc[-1]) if loc else ""
    path = ".".join(str(p) for p in loc)

    if kind == "extra_forbidden":
        # Special-case the unknown-module-name error so users get
        # "Unknown module: 'nucleii'" instead of "Unknown option: 'nucleii'".
        if len(loc) == 3 and loc[0] == "config" and loc[1] == "modules":
            return f'Unknown module: "{field}"'
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

    # Fallback to pydantic's own message
    return err["msg"] if err.get("msg") else f"validation error at {path}"


def _format_errors(exc: ValidationError) -> list[PresetValidationError]:
    out: list[PresetValidationError] = []
    for err in exc.errors():
        where, path = _classify_loc(err["loc"])
        out.append(PresetValidationError(where=where, path=path, message=_format_msg(err)))
    return out


def validate_preset(preset_dict: Any, module_loader=None) -> list[PresetValidationError]:
    """
    Validate a preset dict against BBOT's composite schema.

    Returns a list of `PresetValidationError` objects. An empty list means
    the preset is valid. Errors from all layers are aggregated in a single
    pass, so a user with multiple typos sees them all at once.

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

    # Single-pass validation against the composite schema
    try:
        module_loader.validation_schema.model_validate(preset_dict)
    except ValidationError as e:
        errors.extend(_format_errors(e))

    # Module names listed in top-level `modules`/`output_modules`/`exclude_modules`
    # aren't covered by the composite schema (they're a list of strings, not a
    # nested mapping). Check them here.
    known_modules = set(module_loader.all_module_choices)
    for key in ("modules", "output_modules", "exclude_modules"):
        for name in preset_dict.get(key) or []:
            if name not in known_modules:
                errors.append(
                    PresetValidationError(
                        where="preset",
                        path=key,
                        message=f'Unknown module: "{name}"',
                    )
                )

    return errors


def validate_preset_file(path: str | Path, **kwargs) -> list[PresetValidationError]:
    """Convenience wrapper for validating a YAML preset file on disk."""
    import yaml

    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return [PresetValidationError("preset", "", f"Expected a YAML mapping, got {type(data).__name__}")]
    return validate_preset(data, **kwargs)


__all__ = ["PresetValidationError", "validate_preset", "validate_preset_file"]
