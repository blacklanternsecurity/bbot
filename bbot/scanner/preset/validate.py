"""
Public `validate_preset()` API for BBOT presets.

Given a preset-as-dict (i.e. what comes out of a YAML file before it's
instantiated), return a list of human-readable errors in three layers:

1. Top-level preset keys (e.g. `modlues:` typo)
2. Global config (e.g. `scope.strct`, `web.sslverify`)
3. Per-module config (e.g. `modules.nuclei.tgas`)

Errors are aggregated — a user with multiple typos gets all the errors at once
rather than having to fix one at a time. The caller decides whether to raise
or just print them.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from pydantic import ValidationError

from bbot.core.config.models import BBOTConfig, BaseModuleConfig, PresetSchema


log = logging.getLogger("bbot.presets.validate")


@dataclass
class PresetValidationError:
    """A single validation problem. Stringifies to a human-readable message."""

    where: str  # "preset", "config", "module:<name>"
    path: str  # dotted location, e.g. "scope.strict" or ""
    message: str  # pydantic-derived message, reformatted

    def __str__(self) -> str:
        loc = f"{self.where}:{self.path}" if self.path else self.where
        return f"[{loc}] {self.message}"


def _format_pydantic_errors(exc: ValidationError, where: str) -> list[PresetValidationError]:
    out: list[PresetValidationError] = []
    for err in exc.errors():
        path = ".".join(str(p) for p in err["loc"])
        kind = err["type"]
        input_value = err.get("input")
        if kind == "extra_forbidden":
            msg = f"Unknown option: {path!r}"
            if input_value is not None and isinstance(input_value, (str, int, bool, float)):
                msg += f" (value: {input_value!r})"
        elif kind in {"int_parsing", "int_type"}:
            msg = f"Expected an integer, got {type(input_value).__name__}: {input_value!r}"
        elif kind in {"bool_parsing", "bool_type"}:
            msg = f"Expected a boolean, got {type(input_value).__name__}: {input_value!r}"
        elif kind in {"string_type"}:
            msg = f"Expected a string, got {type(input_value).__name__}: {input_value!r}"
        elif kind == "list_type":
            msg = f"Expected a list, got {type(input_value).__name__}"
        elif kind == "missing":
            msg = "Required option is missing"
        else:
            msg = err["msg"]
        out.append(PresetValidationError(where=where, path=path, message=msg))
    return out


def _get_module_config_class(module_name: str, module_loader) -> Optional[type[BaseModuleConfig]]:
    """
    Return the module's `Config` class, or None if the module doesn't declare one
    (legacy `options`/`options_desc` dict modules).
    """
    preloaded = module_loader.preloaded().get(module_name)
    if not preloaded:
        return None
    module_path = Path(preloaded["path"])
    namespace = preloaded["namespace"]
    full_namespace = f"{namespace}.{module_name}"

    # Re-import by path. Uses the existing importlib pattern from ModuleLoader.load_module.
    spec = importlib.util.spec_from_file_location(full_namespace, str(module_path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        log.debug(f"Could not import {module_name} for validation: {e}")
        return None

    # Find the module class (same heuristic as ModuleLoader.load_module)
    for attr_name in vars(mod):
        value = getattr(mod, attr_name)
        if not hasattr(value, "watched_events") or not hasattr(value, "produced_events"):
            continue
        if not isinstance(getattr(value, "watched_events"), list):
            continue
        if getattr(value, "__name__", "").lower() != module_name.lower():
            continue
        cfg = getattr(value, "Config", None)
        if cfg is not None and isinstance(cfg, type) and issubclass(cfg, BaseModuleConfig):
            return cfg
        return None
    return None


def _modules_referenced(preset_dict: dict, config_dict: dict) -> set[str]:
    """Every module mentioned anywhere in the preset — enabled, configured, or both."""
    names: set[str] = set()
    for key in ("modules", "output_modules", "exclude_modules"):
        names.update(preset_dict.get(key) or [])
    modules_config = config_dict.get("modules") or {}
    if isinstance(modules_config, dict):
        names.update(modules_config.keys())
    return names


def validate_preset(
    preset_dict: dict,
    module_loader=None,
    *,
    validate_modules: bool = True,
    known_modules: Optional[Iterable[str]] = None,
) -> list[PresetValidationError]:
    """
    Validate a preset dict against BBOT's schemas.

    Returns a list of `PresetValidationError` objects. An empty list means the
    preset is valid. The function aggregates errors across all three layers
    (preset, config, per-module) so a user with multiple typos sees them all.

    Args:
        preset_dict: Preset as a plain dict (e.g. from `yaml.safe_load`).
        module_loader: Optional module loader for per-module validation. Falls
            back to the global MODULE_LOADER if not provided. If neither is
            available, per-module validation is skipped.
        validate_modules: If False, only validate preset top-level keys and the
            global config tree (skip per-module Config validation).
        known_modules: Optional set of known module names. If provided, module
            names not in this set are reported as errors. Defaults to the
            module loader's known modules.

    Examples:
        >>> errors = validate_preset({"modlues": ["nuclei"]})
        >>> print(errors[0])
        [preset:modlues] Unknown option: 'modlues' (value: ['nuclei'])
    """
    errors: list[PresetValidationError] = []

    if not isinstance(preset_dict, dict):
        return [PresetValidationError("preset", "", f"Expected a dict, got {type(preset_dict).__name__}")]

    # 1. Top-level preset keys
    try:
        PresetSchema.model_validate(preset_dict)
    except ValidationError as e:
        errors.extend(_format_pydantic_errors(e, where="preset"))

    # 2. Global config tree
    config_dict = preset_dict.get("config") or {}
    if not isinstance(config_dict, dict):
        errors.append(
            PresetValidationError("config", "", f"`config` must be a dict, got {type(config_dict).__name__}")
        )
        config_dict = {}
    else:
        # Exclude the `modules` section from root-level BBOTConfig validation;
        # per-module schemas are validated separately below.
        config_for_root = {k: v for k, v in config_dict.items() if k != "modules"}
        try:
            BBOTConfig.model_validate(config_for_root)
        except ValidationError as e:
            errors.extend(_format_pydantic_errors(e, where="config"))

    # 3. Per-module config
    if validate_modules:
        if module_loader is None:
            try:
                from bbot.core.modules import MODULE_LOADER

                module_loader = MODULE_LOADER
            except Exception:
                module_loader = None

        referenced = _modules_referenced(preset_dict, config_dict)

        if module_loader is not None:
            if known_modules is None:
                known_modules = set(module_loader.all_module_choices)
            else:
                known_modules = set(known_modules)

            modules_config = config_dict.get("modules") or {}
            for name in sorted(referenced):
                if name not in known_modules:
                    errors.append(PresetValidationError("preset", "modules", f'Unknown module: "{name}"'))
                    continue

                raw = modules_config.get(name) or {}
                if not isinstance(raw, dict):
                    errors.append(
                        PresetValidationError(
                            f"module:{name}",
                            "",
                            f"module config must be a dict, got {type(raw).__name__}",
                        )
                    )
                    continue

                cfg_cls = _get_module_config_class(name, module_loader)
                if cfg_cls is None:
                    # legacy module — no Config class yet. Skip strict validation.
                    continue
                try:
                    cfg_cls.model_validate(raw)
                except ValidationError as e:
                    errors.extend(_format_pydantic_errors(e, where=f"module:{name}"))

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


def _assert_preset_valid(preset_dict: dict, **kwargs) -> None:
    """Raise if a preset dict has any validation errors. Tests use this."""
    from bbot.errors import ValidationError as BBOTValidationError

    errs = validate_preset(preset_dict, **kwargs)
    if errs:
        raise BBOTValidationError("\n".join(str(e) for e in errs))
