import os
import re
import ast
import sys
import stat
import yaml
import atexit
import shutil
import pickle
import logging
import tempfile
import importlib
import traceback
from copy import copy
from pathlib import Path
from contextlib import suppress

from bbot.core import CORE
from bbot.errors import BBOTError
from bbot.logger import log_to_stderr

from .flags import flag_descriptions
from .shared_deps import SHARED_DEPS
from .helpers.misc import (
    list_files,
    sha1,
    search_dict_by_key,
    search_format_dict,
    make_table,
    os_platform,
    mkdir,
)


log = logging.getLogger("bbot.module_loader")


class _SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")


bbot_code_dir = Path(__file__).parent.parent


# Bump when the preloader's output schema or validation rules change. Folded
# into the per-module cache_key so stale entries from older bbot versions get
# rebuilt instead of silently bypassing new checks.
PRELOAD_CACHE_VERSION = 3


_UNEVALUATED = object()


def _eval_ast_default(node):
    """
    Extract a literal default value from an AST node. Returns _UNEVALUATED if
    the node can't be resolved statically (e.g. `default_factory=lambda: ...`
    or a non-constant expression). Preload uses this for display-time defaults
    only; actual validation happens at bake time against the real pydantic
    Config class.
    """
    if node is None:
        return _UNEVALUATED
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        # Recognize a few common default_factory values.
        if isinstance(node, ast.Name):
            return {"list": [], "dict": {}, "set": set(), "tuple": (), "str": "", "int": 0, "float": 0.0}.get(
                node.id, _UNEVALUATED
            )
        return _UNEVALUATED


def _exec_config_class(source: str, module_name: str):
    """
    Execute a `class Config(BaseModuleConfig):` snippet in a controlled
    namespace and return the resulting class. The namespace provides exactly
    what a Config block is allowed to reference: the typing primitives,
    pydantic's `Field` factory and validator decorators, and `BaseModuleConfig`.

    This replaces parsing annotations as strings: pydantic handles every
    valid type expression (`Optional[str]`, `Literal["a", "b"]`,
    `list[Union[int, str]]`, …) without any hand-rolled resolver.
    """
    from typing import Annotated, Any, Dict, List, Literal, Optional, Set, Tuple, Union
    from pydantic import AfterValidator, BeforeValidator, field_validator, model_validator
    from bbot.core.config.models import BaseModuleConfig, ConfidenceLiteral, Field, SeverityLiteral

    namespace: dict = {
        "Annotated": Annotated,
        "Any": Any,
        "Dict": Dict,
        "List": List,
        "Literal": Literal,
        "Optional": Optional,
        "Set": Set,
        "Tuple": Tuple,
        "Union": Union,
        "Field": Field,
        "field_validator": field_validator,
        "model_validator": model_validator,
        "BeforeValidator": BeforeValidator,
        "AfterValidator": AfterValidator,
        "BaseModuleConfig": BaseModuleConfig,
        "SeverityLiteral": SeverityLiteral,
        "ConfidenceLiteral": ConfidenceLiteral,
    }
    try:
        exec(source, namespace)
    except Exception as e:
        raise BBOTError(
            f'module "{module_name}" has an invalid Config class ({type(e).__name__}: {e}). '
            "Config blocks may only reference: Optional, Union, Literal, Any, List, Dict, Tuple, Set, "
            "Field, field_validator, model_validator, BeforeValidator, AfterValidator, BaseModuleConfig, "
            "and Python builtins."
        ) from e
    cfg = namespace.get("Config")
    if cfg is None:
        raise BBOTError(f'module "{module_name}": Config snippet did not define a class named "Config"')
    return cfg


def _build_validation_schema(preloaded: dict):
    """
    Build the composite preset validation schema.

    Structure:
        FullPresetSchema
          ├── (all PresetSchema fields — target, modules, flags, …)
          └── config: FullBBOTConfig
                      ├── (all BBOTConfig fields — scope, dns, web, …)
                      └── modules: ModulesSchema
                                   ├── nuclei:  NucleiModuleConfig
                                   ├── httpx:   HttpxModuleConfig
                                   ├── sslcert: SslcertModuleConfig
                                   └── … one field per known module

    A single `FullPresetSchema.model_validate(preset_dict)` call then catches
    every class of error in one pass:
      - top-level preset typos (extra='forbid' on PresetSchema)
      - global config typos / wrong types (extra='forbid' on BBOTConfig)
      - unknown module names (extra='forbid' on ModulesSchema)
      - wrong module option names / wrong types (extra='forbid' per module)
    """
    import warnings
    from typing import Optional
    from pydantic import ConfigDict, Field, create_model
    from bbot.core.config.models import BaseModuleConfig, BBOTConfig, PresetSchema

    module_fields = {}
    for name, data in preloaded.items():
        source = data.get("config_source")
        if not source:
            # Module declares no Config — only the universal options apply.
            field_type = BaseModuleConfig
        else:
            try:
                field_type = _exec_config_class(source, name)
            except BBOTError as e:
                # The Config references a name not available in the isolated exec
                # namespace (a module-level constant, imported type, Enum, …); it's
                # valid at real import time. Don't reject the module — accept any
                # config for it (its own options just aren't strictly validated here).
                log.debug(f"{e} -- accepting any config for module '{name}'")
                field_type = dict
        module_fields[name] = (Optional[field_type], Field(default=None))

    # Some module names (e.g. `json`) shadow BaseModel's deprecated method
    # names and trigger a UserWarning. The field still validates correctly;
    # silence the noise.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r'Field name ".+" in ".+" shadows an attribute in parent "BaseModel"',
            category=UserWarning,
        )
        ModulesSchema = create_model(
            "ModulesSchema",
            __config__=ConfigDict(extra="forbid"),
            **module_fields,
        )
        FullBBOTConfig = create_model(
            "FullBBOTConfig",
            __base__=BBOTConfig,
            modules=(Optional[ModulesSchema], Field(default=None)),
        )
        FullPresetSchema = create_model(
            "FullPresetSchema",
            __base__=PresetSchema,
            config=(Optional[FullBBOTConfig], Field(default=None)),
        )
    return FullPresetSchema


def _extract_pydantic_config(config_class: ast.ClassDef) -> tuple[dict, dict, set, set, dict]:
    """
    Walk a `class Config(BaseModuleConfig):` block and extract
    `(defaults, descriptions, sensitive, mandatory, types)` -- cheap metadata
    used for `bbot -l`, type-directed config coercion, and similar listing
    paths, without importing or exec-ing anything.

    `types` maps each field name to its raw annotation string (e.g.
    `"bool"`, `"Union[str, list[str]]"`, `"Literal['manual', 'severe']"`).
    The actual typed pydantic class is built later via `_exec_config_class`
    on the captured source text.
    """
    defaults: dict = {}
    descriptions: dict = {}
    sensitive: set = set()
    mandatory: set = set()
    types: dict = {}
    for node in config_class.body:
        # `model_config = ConfigDict(...)` etc. are plain assigns, not typed -- skip.
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        name = node.target.id
        if name.startswith("_"):
            continue

        types[name] = ast.unparse(node.annotation)
        default = _UNEVALUATED
        description = ""
        is_sensitive = False
        is_mandatory = False

        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "Field":
            # Field(default, description="...", default_factory=..., sensitive=..., mandatory=..., ...)
            # - first positional arg is the default, if given
            if value.args:
                default = _eval_ast_default(value.args[0])
            for kw in value.keywords:
                if kw.arg == "default":
                    default = _eval_ast_default(kw.value)
                elif kw.arg == "default_factory":
                    default = _eval_ast_default(kw.value)
                elif kw.arg == "description":
                    with suppress(ValueError, TypeError, SyntaxError):
                        description = ast.literal_eval(kw.value)
                elif kw.arg == "sensitive":
                    with suppress(ValueError, TypeError, SyntaxError):
                        is_sensitive = bool(ast.literal_eval(kw.value))
                elif kw.arg == "mandatory":
                    with suppress(ValueError, TypeError, SyntaxError):
                        is_mandatory = bool(ast.literal_eval(kw.value))
                elif kw.arg == "json_schema_extra":
                    with suppress(ValueError, TypeError, SyntaxError):
                        extra = ast.literal_eval(kw.value)
                        if isinstance(extra, dict):
                            is_sensitive = is_sensitive or bool(extra.get("sensitive"))
                            is_mandatory = is_mandatory or bool(extra.get("mandatory"))
        elif value is not None:
            default = _eval_ast_default(value)

        if default is _UNEVALUATED:
            # couldn't statically determine; fall back to None so listing still works
            default = None
        defaults[name] = default
        descriptions[name] = description
        if is_sensitive:
            sensitive.add(name)
        if is_mandatory:
            mandatory.add(name)
    return defaults, descriptions, sensitive, mandatory, types


class ModuleLoader:
    """
    Main class responsible for preloading BBOT modules.

    This class is in charge of preloading modules to determine their dependencies.
    Once dependencies are identified, they are installed before the actual module is imported.
    This ensures that all requisite libraries and components are available for the module to function correctly.
    """

    default_module_dir = bbot_code_dir / "modules"

    module_dir_regex = re.compile(r"^[a-z][a-z0-9_]*$")

    # if a module consumes these event types, automatically assume these dependencies
    default_module_deps = {"HTTP_RESPONSE": "http", "URL": "http", "SOCIAL": "social"}

    def __init__(self):
        self.core = CORE

        self._shared_deps = dict(SHARED_DEPS)

        self.__preloaded = {}
        self._configs = {}
        self.flag_choices = set()
        self.all_module_choices = set()
        self.scan_module_choices = set()
        self.output_module_choices = set()
        self.internal_module_choices = set()

        self._preload_cache = None
        # Composite preset-validation schema, built from preloaded modules.
        # Invalidated whenever a new module is preloaded.
        self._validation_schema = None
        self._config_type_index = None

        self._module_dirs = set()
        self._module_dirs_preloaded = set()
        self.add_module_dir(self.default_module_dir)

        # save preload cache before exiting
        atexit.register(self.save_preload_cache)

    def copy(self):
        module_loader_copy = copy(self)
        module_loader_copy.__preloaded = dict(self.__preloaded)
        return module_loader_copy

    @property
    def preload_cache_file(self):
        return self.core.cache_dir / "module_preload_cache"

    @property
    def module_dirs(self):
        return self._module_dirs

    def add_module_dir(self, module_dir):
        module_dir = Path(module_dir).resolve()
        if module_dir in self._module_dirs:
            log.debug(f'Already added custom module dir "{module_dir}"')
            return
        if not module_dir.is_dir():
            log.warning(f'Failed to add custom module dir "{module_dir}", please make sure it exists')
            return
        new_module_dirs = set()
        for _module_dir in self.get_recursive_dirs(module_dir):
            _module_dir = Path(_module_dir).resolve()
            if _module_dir not in self._module_dirs:
                self._module_dirs.add(_module_dir)
                new_module_dirs.add(_module_dir)
        self.preload(module_dirs=new_module_dirs)

    def file_filter(self, file):
        file = file.resolve()
        for part in file.parts:
            if part.endswith("_submodules") or part == "templates":
                return False
        return file.suffix.lower() == ".py" and file.stem not in ["base", "__init__"]

    def preload(self, module_dirs=None):
        """Preloads all BBOT modules.

        This function recursively iterates through each file in the module directories
        and preloads each BBOT module to gather its meta-information and dependencies.

        Args:
            module_dir (str or Path): Directory containing BBOT modules to be preloaded.

        Returns:
            dict: A dictionary where keys are the names of the preloaded modules and
            values are their respective preloaded data.

        Examples:
            >>> preload("/path/to/bbot_modules/")
            {
                "module1": {...},
                "module2": {...},
                ...
            }
        """
        new_modules = False
        if module_dirs is None:
            module_dirs = self.module_dirs

        for module_dir in module_dirs:
            if module_dir in self._module_dirs_preloaded:
                log.debug(f"Already preloaded modules from {module_dir}")
                continue

            log.debug(f"Preloading modules from {module_dir}")
            new_modules = True
            for module_file in list_files(module_dir, filter=self.file_filter):
                module_name = module_file.stem
                module_file = module_file.resolve()

                # try to load from cache
                module_cache_key = (PRELOAD_CACHE_VERSION, str(module_file), tuple(module_file.stat()))
                preloaded = self.preload_cache.get(module_name, {})
                cache_key = preloaded.get("cache_key", ())
                if preloaded and module_cache_key == cache_key:
                    log.debug(f"Preloading {module_name} from cache")
                else:
                    log.debug(f"Preloading {module_name} from disk")
                    if module_dir.name == "modules":
                        namespace = "bbot.modules"
                    else:
                        namespace = f"bbot.modules.{module_dir.name}"
                    try:
                        preloaded = self.preload_module(module_file)
                        if preloaded is None:
                            continue
                        module_type = "scan"
                        if module_dir.name in ("output", "internal"):
                            module_type = str(module_dir.name)

                        disable_auto_module_deps = preloaded.get("disable_auto_module_deps", False)

                        # derive module dependencies from watched event types (only for scan modules)
                        if module_type == "scan" and not disable_auto_module_deps:
                            for event_type in preloaded["watched_events"]:
                                if event_type in self.default_module_deps:
                                    deps_modules = set(preloaded.get("deps", {}).get("modules", []))
                                    deps_modules.add(self.default_module_deps[event_type])
                                    preloaded["deps"]["modules"] = sorted(deps_modules)

                        preloaded["type"] = module_type
                        preloaded["namespace"] = namespace
                        preloaded["cache_key"] = module_cache_key

                    except BBOTError as e:
                        # Intentional, user-facing errors raised from preload_module
                        # (e.g. the pre-3.0 options-dict migration message). Skip the
                        # traceback so the message reads cleanly.
                        log_to_stderr(str(e), level="CRITICAL")
                        sys.exit(1)
                    except Exception:
                        log_to_stderr(f"Error preloading {module_file}\n\n{traceback.format_exc()}", level="CRITICAL")
                        log_to_stderr(f"Error in {module_file.name}", level="CRITICAL")
                        sys.exit(1)

                self.all_module_choices.add(module_name)
                module_type = preloaded.get("type", "scan")
                if module_type == "scan":
                    self.scan_module_choices.add(module_name)
                elif module_type == "output":
                    self.output_module_choices.add(module_name)
                elif module_type == "internal":
                    self.internal_module_choices.add(module_name)

                flags = preloaded.get("flags", [])
                self.flag_choices.update(set(flags))

                self.__preloaded[module_name] = preloaded
                self._configs[module_name] = dict(preloaded.get("config", {}))

            self._module_dirs_preloaded.add(module_dir)

        # update default config with module defaults
        self.core.merge_default({"modules": self.configs()})

        # invalidate the composite validation schema; it'll rebuild lazily
        # on next access now that the set of modules has changed
        if new_modules:
            self._validation_schema = None
            self._config_type_index = None

        return new_modules

    @property
    def preload_cache(self):
        if self._preload_cache is None:
            self._preload_cache = {}
            if self.preload_cache_file.is_file():
                with suppress(Exception):
                    with open(self.preload_cache_file, "rb") as f:
                        self._preload_cache = _SafeUnpickler(f).load()
        return self._preload_cache

    @preload_cache.setter
    def preload_cache(self, value):
        self._preload_cache = value
        mkdir(self.preload_cache_file.parent)
        with open(self.preload_cache_file, "wb") as f:
            pickle.dump(self._preload_cache, f)

    def save_preload_cache(self):
        self.preload_cache = self.__preloaded

    @property
    def _preloaded(self):
        return self.__preloaded

    def get_recursive_dirs(self, *dirs):
        dirs = {Path(d).resolve() for d in dirs}
        for d in list(dirs):
            if not d.is_dir():
                continue
            for p in d.iterdir():
                if p.is_dir() and self.module_dir_regex.match(p.name):
                    dirs.update(self.get_recursive_dirs(p))
        return dirs

    def preloaded(self, type=None):
        preloaded = {}
        if type is not None:
            preloaded = {k: v for k, v in self._preloaded.items() if self.check_type(k, type)}
        else:
            preloaded = dict(self._preloaded)
        return preloaded

    def configs(self, type=None):
        if type is not None:
            return {k: dict(v) for k, v in self._configs.items() if self.check_type(k, type)}
        return {k: dict(v) for k, v in self._configs.items()}

    @property
    def validation_schema(self):
        """
        The composite pydantic schema for validating a full preset dict.

        Built lazily from preloaded module metadata and cached. Rebuilt when
        `preload()` discovers new modules (e.g. after `add_module_dir`).
        """
        if self._validation_schema is None:
            self._validation_schema = _build_validation_schema(self._preloaded)
        return self._validation_schema

    @property
    def config_schema(self):
        """
        The runtime `BBOTConfig` schema with per-module configs grafted in.

        This is `validation_schema.config` (i.e. `FullBBOTConfig`) and is the
        right model to walk a config dict against — used by
        `BBOTCore.no_secrets_config()` and `BBOTCore.secrets_only_config()` to
        partition sensitive fields.
        """
        from bbot.core.config.models import _unwrap_optional

        field = self.validation_schema.model_fields.get("config")
        if field is None:
            from bbot.core.config.models import BBOTConfig

            return BBOTConfig
        return _unwrap_optional(field.annotation)

    @property
    def config_type_index(self):
        """{dotted_config_path: TypeAdapter} for every known config option.

        Built by walking the materialized config schema (`config_schema`, i.e.
        global config + every module's exec'd Config), so a single pydantic
        TypeAdapter per leaf field drives coercion -- no hand-rolled type-name
        parsing. Adapters are memoized by annotation (many fields share e.g.
        `Optional[str]`). Nested models are recursed into via `_field_submodel`,
        so `modules.<name>.<option>` keys fall out of the same walk.
        """
        if self._config_type_index is None:
            from pydantic import ConfigDict, TypeAdapter
            from bbot.core.config.models import _field_submodel

            # coerce_numbers_to_str lets a numeric YAML value (e.g. password: 12345678)
            # validate against a str field; pydantic is otherwise lax-but-not-that-lax.
            adapter_config = ConfigDict(coerce_numbers_to_str=True)
            adapter_cache = {}

            def make_adapter(annotation):
                try:
                    if annotation in adapter_cache:
                        return adapter_cache[annotation]
                    hashable = True
                except TypeError:
                    hashable = False
                try:
                    adapter = TypeAdapter(annotation, config=adapter_config)
                except Exception as e:
                    log.debug(f"config_type_index: no TypeAdapter for {annotation!r}: {e}")
                    adapter = None
                if hashable:
                    adapter_cache[annotation] = adapter
                return adapter

            index = {}

            def walk(model, prefix=""):
                for fname, field in model.model_fields.items():
                    sub = _field_submodel(field)
                    for key in {fname, getattr(field, "alias", None)} - {None}:
                        dotted = f"{prefix}.{key}" if prefix else key
                        if sub is not None:
                            walk(sub, dotted)
                        else:
                            adapter = make_adapter(field.annotation)
                            if adapter is not None:
                                index[dotted] = adapter

            walk(self.config_schema)
            self._config_type_index = index
        return self._config_type_index

    def find_and_replace(self, **kwargs):
        self.__preloaded = search_format_dict(self.__preloaded, **kwargs)
        self._shared_deps = search_format_dict(self._shared_deps, **kwargs)

    def check_type(self, module, type):
        return self._preloaded[module]["type"] == type

    def preload_module(self, module_file):
        """
        Preloads a BBOT module to gather its meta-information and dependencies.

        This function reads a BBOT module file, extracts its attributes such as
        events watched and produced, flags, meta-information, and dependencies.

        Args:
            module_file (str): Path to the BBOT module file.

        Returns:
            dict: A dictionary containing meta-information and dependencies for the module.

        Examples:
            >>> preload_module("bbot/modules/wappalyzer.py")
            {
                "watched_events": [
                    "HTTP_RESPONSE"
                ],
                "produced_events": [
                    "TECHNOLOGY"
                ],
                "flags": [
                    "active",
                    "web",
                    "web-heavy"
                ],
                "meta": {
                    "description": "Extract technologies from web responses"
                },
                "config": {},
                "options_desc": {},
                "hash": "d5a88dd3866c876b81939c920bf4959716e2a374",
                "deps": {
                    "modules": [
                        "http"
                    ]
                    "pip": [
                        "python-Wappalyzer~=0.3.1"
                    ],
                    "pip_constraints": [],
                    "shell": [],
                    "apt": [],
                    "ansible": []
                },
                "sudo": false
            }
        """
        watched_events = set()
        produced_events = set()
        flags = set()
        meta = {}
        deps_modules = set()
        deps_pip = []
        deps_pip_constraints = []
        deps_shell = []
        deps_apt = []
        deps_common = []
        ansible_tasks = []
        config = {}
        options_desc = {}
        options_sensitive: set = set()
        options_mandatory: set = set()
        options_types: dict = {}
        config_source: str | None = None
        legacy_options_keyword: str | None = None
        legacy_options_line: int | None = None
        disable_auto_module_deps = False
        with open(module_file) as f:
            python_code = f.read()
        # take a hash of the code so we can keep track of when it changes
        module_hash = sha1(python_code).hexdigest()
        parsed_code = ast.parse(python_code)

        # discard if the module isn't a valid BBOT module
        is_bbot_module = False
        for root_element in parsed_code.body:
            if type(root_element) == ast.ClassDef:
                for class_attr in root_element.body:
                    if type(class_attr) == ast.Assign and any(
                        target.id in ("watched_events", "produced_events") for target in class_attr.targets
                    ):
                        is_bbot_module = True
                        break

        if not is_bbot_module:
            log.debug(f"Skipping {module_file} as it is not a valid BBOT module")
            return

        for root_element in parsed_code.body:
            # look for classes
            if type(root_element) == ast.ClassDef:
                for class_attr in root_element.body:
                    # nested `class Config(BaseModuleConfig): ...` — the module's config schema
                    if type(class_attr) == ast.ClassDef and class_attr.name == "Config":
                        config_fields, config_descs, config_sens, config_mand, config_types = _extract_pydantic_config(
                            class_attr
                        )
                        config.update(config_fields)
                        options_desc.update(config_descs)
                        options_sensitive.update(config_sens)
                        options_mandatory.update(config_mand)
                        options_types.update(config_types)
                        # capture the class source verbatim; schema build re-execs it
                        config_source = ast.get_source_segment(python_code, class_attr)
                        continue

                    # annotated legacy form (`options: dict = {...}` -> ast.AnnAssign) must
                    # also be caught, otherwise it slips the 3.0 legacy-options rejection below
                    if (
                        legacy_options_keyword is None
                        and isinstance(class_attr, ast.AnnAssign)
                        and isinstance(class_attr.target, ast.Name)
                        and class_attr.target.id in ("options", "options_desc")
                    ):
                        legacy_options_keyword = class_attr.target.id
                        legacy_options_line = class_attr.lineno

                    if not type(class_attr) == ast.Assign:
                        continue

                    # legacy options/options_desc dict: record so we can fail
                    # with a migration hint after the walk completes
                    if legacy_options_keyword is None:
                        for target in class_attr.targets:
                            if isinstance(target, ast.Name) and target.id in ("options", "options_desc"):
                                legacy_options_keyword = target.id
                                legacy_options_line = class_attr.lineno
                                break

                    # module metadata
                    if type(class_attr.value) == ast.Dict:
                        if any(target.id == "meta" for target in class_attr.targets):
                            meta = ast.literal_eval(class_attr.value)

                    # class attributes that are lists
                    if type(class_attr.value) == ast.List:
                        # flags
                        if any(target.id == "flags" for target in class_attr.targets):
                            for flag in class_attr.value.elts:
                                if type(flag.value) == str:
                                    flags.add(flag.value)
                        # watched events
                        elif any(target.id == "watched_events" for target in class_attr.targets):
                            for event_type in class_attr.value.elts:
                                if type(event_type.value) == str:
                                    watched_events.add(event_type.value)
                        # produced events
                        elif any(target.id == "produced_events" for target in class_attr.targets):
                            for event_type in class_attr.value.elts:
                                if type(event_type.value) == str:
                                    produced_events.add(event_type.value)

                        # bbot module dependencies
                        elif any(target.id == "deps_modules" for target in class_attr.targets):
                            for dep_module in class_attr.value.elts:
                                if type(dep_module.value) == str:
                                    deps_modules.add(dep_module.value)
                        # python dependencies
                        elif any(target.id == "deps_pip" for target in class_attr.targets):
                            for dep_pip in class_attr.value.elts:
                                if type(dep_pip.value) == str:
                                    deps_pip.append(dep_pip.value)
                        elif any(target.id == "deps_pip_constraints" for target in class_attr.targets):
                            for dep_pip in class_attr.value.elts:
                                if type(dep_pip.value) == str:
                                    deps_pip_constraints.append(dep_pip.value)
                        # apt dependencies
                        elif any(target.id == "deps_apt" for target in class_attr.targets):
                            for dep_apt in class_attr.value.elts:
                                if type(dep_apt.value) == str:
                                    deps_apt.append(dep_apt.value)
                        # bash dependencies
                        elif any(target.id == "deps_shell" for target in class_attr.targets):
                            for dep_shell in class_attr.value.elts:
                                deps_shell.append(ast.literal_eval(dep_shell))
                        # ansible playbook
                        elif any(target.id == "deps_ansible" for target in class_attr.targets):
                            ansible_tasks = ast.literal_eval(class_attr.value)
                        # shared/common module dependencies
                        elif any(target.id == "deps_common" for target in class_attr.targets):
                            for dep_common in class_attr.value.elts:
                                if type(dep_common.value) == str:
                                    deps_common.append(dep_common.value)

                    # class attributes that are booleans
                    if type(class_attr.value) == ast.Constant:
                        if any(target.id == "_disable_auto_module_deps" for target in class_attr.targets):
                            if type(class_attr.value.value) == bool:
                                disable_auto_module_deps = class_attr.value.value

        # Reject the pre-3.0 options/options_desc dict format. Those dicts are
        # silently ignored by the new loader: defaults disappear and setting
        # them via -c or YAML emits misleading "did you mean ...?" suggestions
        # pointing at unrelated modules.
        module_name = module_file.stem
        if legacy_options_keyword is not None and config_source is None:
            raise BBOTError(
                f'Module "{module_name}" ({module_file}:{legacy_options_line}) declares a legacy '
                f"`{legacy_options_keyword}` dict, which is no longer supported in BBOT 3.0+.\n\n"
                f"Replace the `options` / `options_desc` dicts with a nested\n"
                f"`class Config(BaseModuleConfig)` schema. For example:\n\n"
                f"    from bbot.core.config.models import BaseModuleConfig, Field\n\n"
                f"    class {module_name}(BaseModule):\n"
                f"        ...\n"
                f"        class Config(BaseModuleConfig):\n"
                f'            api_key: str = Field("", description="API key", sensitive=True)\n'
                f'            max_results: int = Field(100, description="Max results to return")\n'
            )

        for task in ansible_tasks:
            if "become" not in task:
                task["become"] = False
            # don't sudo brew
            elif os_platform() == "darwin" and ("package" in task and task.get("become", False) is True):
                task["become"] = False

        preloaded_data = {
            "path": str(module_file.resolve()),
            "watched_events": sorted(watched_events),
            "produced_events": sorted(produced_events),
            "flags": sorted(flags),
            "meta": meta,
            "config": config,
            "options_desc": options_desc,
            "options_sensitive": sorted(options_sensitive),
            "options_mandatory": sorted(options_mandatory),
            "options_types": options_types,
            "config_source": config_source,
            "hash": module_hash,
            "deps": {
                "modules": sorted(deps_modules),
                "pip": deps_pip,
                "pip_constraints": deps_pip_constraints,
                "shell": deps_shell,
                "apt": deps_apt,
                "ansible": ansible_tasks,
                "common": deps_common,
            },
            "sudo": len(deps_apt) > 0,
            "disable_auto_module_deps": disable_auto_module_deps,
        }
        ansible_task_list = list(ansible_tasks)
        for dep_common in deps_common:
            try:
                ansible_task_list.extend(self._shared_deps[dep_common])
            except KeyError:
                common_choices = ",".join(self._shared_deps)
                raise BBOTError(
                    f'Error while preloading module "{module_file}": No shared dependency named "{dep_common}" (choices: {common_choices})'
                )
        for ansible_task in ansible_task_list:
            if any(x is True for x in search_dict_by_key("become", ansible_task)) or any(
                x is True for x in search_dict_by_key("ansible_become", ansible_tasks)
            ):
                preloaded_data["sudo"] = True
        return preloaded_data

    def load_modules(self, module_names):
        modules = {}
        for module_name in module_names:
            try:
                module = self.load_module(module_name)
            except ModuleNotFoundError as e:
                raise BBOTError(
                    f"Error loading module {module_name}: {e}. You may have leftover artifacts from an older version of BBOT. Try deleting/renaming your '~/.bbot' directory."
                ) from e
            modules[module_name] = module
        return modules

    def load_module(self, module_name):
        """Loads a BBOT module by its name.

        Imports the module from its namespace, locates its class, and returns it.
        Identifies modules based on the presence of `watched_events` and `produced_events` attributes.

        Args:
            module_name (str): The name of the module to load.

        Returns:
            object: The loaded module class object.

        Examples:
            >>> module = load_module("example_module")
            >>> isinstance(module, object)
            True
        """
        preloaded = self._preloaded[module_name]
        namespace = preloaded["namespace"]
        try:
            module_path = preloaded["path"]
        except KeyError:
            module_path = preloaded["cache_key"][0]
        full_namespace = f"{namespace}.{module_name}"

        spec = importlib.util.spec_from_file_location(full_namespace, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_namespace] = module
        spec.loader.exec_module(module)

        # for every top-level variable in the .py file
        for variable in module.__dict__.keys():
            # get its value
            value = getattr(module, variable)
            with suppress(AttributeError):
                # if it has watched_events and produced_events
                if all(
                    type(a) == list
                    for a in (getattr(value, "watched_events", None), getattr(value, "produced_events", None))
                ):
                    # and if its variable name matches its filename
                    if value.__name__.lower() == module_name.lower():
                        value._name = module_name
                        # then we have a module
                        return value

    def check_dependency(self, event_type, modname, produced):
        if event_type not in produced:
            return False
        if produced[event_type] == {modname}:
            return False
        return True

    @staticmethod
    def add_or_create(d, k, *items):
        try:
            d[k].update(set(items))
        except KeyError:
            d[k] = set(items)

    def modules_table(self, modules=None, mod_type=None, include_author=False, include_created_date=False):
        """Generates a table of module information.

        Constructs a table to display information such as module name, type, and event details.

        Args:
            modules (list, optional): List of module names to include in the table.
            mod_type (str, optional): Type of modules to include ('scan', 'output', 'internal').

        Returns:
            str: A formatted table string.

        Examples:
            >>> print(modules_table(["portscan"]))
            +----------+--------+-----------------+------------------------------+------------------+----------------------+-------------------+
            | Module   | Type   | Needs API Key   | Description                  | Flags            | Consumed Events      | Produced Events   |
            +==========+========+=================+==============================+==================+======================+===================+
            | portscan | scan   | No              | Execute port scans           | active, portscan | DNS_NAME, IP_ADDRESS | OPEN_TCP_PORT     |
            +----------+--------+-----------------+------------------------------+------------------+----------------------+-------------------+
        """

        table = []
        header = ["Module", "Type", "Needs API Key", "Description", "Flags", "Consumed Events", "Produced Events"]
        if include_author:
            header.append("Author")
        if include_created_date:
            header.append("Created Date")
        maxcolwidths = [20, 10, 5, 30, 30, 20, 20]
        for module_name, preloaded in self.filter_modules(modules, mod_type):
            module_type = preloaded["type"]
            consumed_events = sorted(preloaded.get("watched_events", []))
            produced_events = sorted(preloaded.get("produced_events", []))
            flags = sorted(preloaded.get("flags", []))
            meta = preloaded.get("meta", {})
            api_key_required = "Yes" if preloaded.get("options_mandatory") else "No"
            description = meta.get("description", "")
            row = [
                module_name,
                module_type,
                api_key_required,
                description,
                ", ".join(flags),
                ", ".join(consumed_events),
                ", ".join(produced_events),
            ]
            if include_author:
                author = meta.get("author", "")
                row.append(author)
            if include_created_date:
                created_date = meta.get("created_date", "")
                row.append(created_date)
            table.append(row)
        return make_table(table, header, maxcolwidths=maxcolwidths)

    def modules_options(self, modules=None, mod_type=None):
        """
        Return a list of module options
        """
        modules_options = {}
        for module_name, preloaded in self.filter_modules(modules, mod_type):
            modules_options[module_name] = []
            module_options = preloaded["config"]
            module_options_desc = preloaded["options_desc"]
            module_options_types = preloaded.get("options_types", {})
            for k, v in sorted(module_options.items(), key=lambda x: x[0]):
                option_name = f"modules.{module_name}.{k}"
                option_type = module_options_types.get(k, type(v).__name__)
                option_description = module_options_desc[k]
                modules_options[module_name].append((option_name, option_type, option_description, str(v)))
        return modules_options

    def modules_options_table(self, modules=None, mod_type=None):
        table = []
        header = ["Config Option", "Type", "Description", "Default"]
        for module_options in self.modules_options(modules, mod_type).values():
            table += module_options
        return make_table(table, header)

    def flags(self, flags=None):
        _flags = {}
        for module_name, preloaded in self.preloaded().items():
            for flag in preloaded.get("flags", []):
                if not flags or flag in flags:
                    try:
                        _flags[flag].add(module_name)
                    except KeyError:
                        _flags[flag] = {module_name}

        _flags = sorted(_flags.items(), key=lambda x: x[0])
        _flags = sorted(_flags, key=lambda x: len(x[-1]), reverse=True)
        return _flags

    def flags_table(self, flags=None):
        table = []
        header = ["Flag", "# Modules", "Description", "Modules"]
        maxcolwidths = [20, 5, 40, 80]
        _flags = self.flags(flags=flags)
        for flag, modules in _flags:
            description = flag_descriptions.get(flag, "")
            table.append([flag, f"{len(modules)}", description, ", ".join(sorted(modules))])
        return make_table(table, header, maxcolwidths=maxcolwidths)

    def events(self):
        consuming_events = {}
        producing_events = {}
        for module_name, preloaded in self.preloaded().items():
            consumed = preloaded.get("watched_events", [])
            produced = preloaded.get("produced_events", [])
            for c in consumed:
                try:
                    consuming_events[c].add(module_name)
                except KeyError:
                    consuming_events[c] = {module_name}
            for c in produced:
                try:
                    producing_events[c].add(module_name)
                except KeyError:
                    producing_events[c] = {module_name}
        return consuming_events, producing_events

    def events_table(self):
        table = []
        header = ["Event Type", "# Consuming Modules", "# Producing Modules", "Consuming Modules", "Producing Modules"]
        consuming_events, producing_events = self.events()
        all_event_types = sorted(set(consuming_events).union(set(producing_events)))
        for e in all_event_types:
            consuming = sorted(consuming_events.get(e, []))
            producing = sorted(producing_events.get(e, []))
            table.append([e, len(consuming), len(producing), ", ".join(consuming), ", ".join(producing)])
        return make_table(table, header)

    def filter_modules(self, modules=None, mod_type=None):
        if modules is None:
            module_list = list(self.preloaded(type=mod_type).items())
        else:
            module_list = [(m, self._preloaded[m]) for m in modules]
        module_list.sort(key=lambda x: x[0])
        module_list.sort(key=lambda x: "passive" in x[-1]["flags"])
        module_list.sort(key=lambda x: x[-1]["type"], reverse=True)
        return module_list

    def _generated_config_files(self):
        """The config files BBOT generates, each paired with the content it
        should currently hold and the CLI flag that regenerates it.

        Creation and reset both iterate this list, so the two files stay fully
        independent: a `secrets.yml` full of API keys is never touched just
        because `bbot.yml`'s options changed, and vice versa.
        """
        files = self.core.files_config
        config_obj = dict(self.core.default_config)
        return [
            {
                "label": "config",
                "path": files.config_filename,
                "content": self.core.no_secrets_config(config_obj),
                "secret": False,
                "reset_flag": "--reset-config",
            },
            {
                "label": "secrets",
                "path": files.secrets_filename,
                "content": self.core.secrets_only_config(config_obj),
                "secret": True,
                "reset_flag": "--reset-secrets",
            },
        ]

    def ensure_config_files(self):
        """Create any of the user's generated config files that are missing.

        Each file is a fully-commented snapshot of the current defaults,
        written once and never overwritten.
        """
        mkdir(self.core.files_config.config_dir)
        for spec in self._generated_config_files():
            if not spec["path"].exists():
                log_to_stderr(f"Creating BBOT {spec['label']} at {spec['path']}")
                self._write_config_template(spec["path"], spec["content"], secret=spec["secret"])

    def reset_config_files(self, labels):
        """Regenerate the named generated config files (`"config"` and/or
        `"secrets"`) from current defaults, backing up existing files to
        `*.bak`. Returns the backup paths.

        Destructive: a regenerated file is a fresh commented template, so any
        options the user uncommented in it are not carried over.
        """
        mkdir(self.core.files_config.config_dir)
        backups = []
        for spec in self._generated_config_files():
            if spec["label"] not in labels:
                continue
            path = spec["path"]
            if path.exists():
                backup = self._next_backup_path(path)
                # copy2 preserves the file's permissions, so a backup of a
                # hardened secrets.yml stays just as locked-down
                shutil.copy2(path, backup)
                backups.append(backup)
            self._write_config_template(path, spec["content"], secret=spec["secret"])
        return backups

    @staticmethod
    def _next_backup_path(path):
        """First free `<name>.bak`, `<name>.bak.1`, `<name>.bak.2`, ... so an
        existing backup from a previous reset isn't clobbered."""
        backup = path.with_name(path.name + ".bak")
        i = 1
        while backup.exists():
            backup = path.with_name(f"{path.name}.bak.{i}")
            i += 1
        return backup

    @classmethod
    def _write_config_template(cls, path, config_dict, secret=False):
        header = (
            "# NOTICE: THESE ENTRIES ARE COMMENTED BY DEFAULT\n"
            "# Please be sure to uncomment when inserting API keys, etc.\n"
        )
        yaml_str = yaml.dump(config_dict, sort_keys=False)
        yaml_str = header + "\n".join(f"# {line}" for line in yaml_str.splitlines())
        if secret:
            cls._write_secret_text(path, yaml_str)
        else:
            with open(str(path), "w") as f:
                f.write(yaml_str)

    @staticmethod
    def _write_secret_text(path, text):
        """Write a secrets file so it is never readable by anyone but the owner,
        even for an instant. The content is written to a private temp file
        (mkstemp creates it 0600) and atomically renamed into place; an existing
        file's own permissions are preserved in case the user hardened them
        further (e.g. 0400). If owner-only permissions can't be guaranteed, the
        secret is not written."""
        path = Path(path)
        mode = 0o600
        with suppress(FileNotFoundError):
            existing_mode = stat.S_IMODE(path.stat().st_mode)
            # keep the user's perms only if they're already owner-only
            if not existing_mode & 0o077:
                mode = existing_mode
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "w") as f:
                f.write(text)
            if stat.S_IMODE(os.stat(tmp).st_mode) & 0o077:
                raise BBOTError(f"Refusing to write secrets to {path}: could not restrict permissions to owner-only")
            os.replace(tmp, str(path))
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(tmp)
            raise


MODULE_LOADER = ModuleLoader()
