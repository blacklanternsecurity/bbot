import os
import yaml
import logging
import omegaconf
import traceback
from copy import copy
from pathlib import Path
from contextlib import suppress

from .path import PRESET_PATH

from bbot.core import CORE
from bbot.core.errors import *
from bbot.core.event.base import make_event
from bbot.core.helpers.misc import make_table, mkdir


log = logging.getLogger("bbot.presets")


# cache default presets to prevent having to reload from disk
DEFAULT_PRESETS = None


class Preset:

    def __init__(
        self,
        *targets,
        whitelist=None,
        blacklist=None,
        modules=None,
        output_modules=None,
        exclude_modules=None,
        internal_modules=None,
        flags=None,
        require_flags=None,
        exclude_flags=None,
        verbose=False,
        debug=False,
        silent=False,
        config=None,
        strict_scope=False,
        module_dirs=None,
        include=None,
        output_dir=None,
        scan_name=None,
        name=None,
        description=None,
        conditions=None,
        force=False,
        _exclude=None,
        _log=False,
    ):
        self._log = _log
        self.scan = None
        self._args = None
        self._environ = None
        self._helpers = None
        self._module_loader = None
        self._yaml_str = ""

        self._modules = set()

        self._exclude_modules = set()
        self._require_flags = set()
        self._exclude_flags = set()
        self._flags = set()

        self.force = force

        self._verbose = False
        self._debug = False
        self._silent = False

        self.output_dir = output_dir
        self.scan_name = scan_name
        self.name = name or ""
        self.description = description or ""
        self.conditions = []
        if conditions is not None:
            for condition in conditions:
                self.conditions.append((self.name, condition))

        self._preset_files_loaded = set()
        if _exclude is not None:
            for _filename in _exclude:
                self._preset_files_loaded.add(Path(_filename).resolve())

        # bbot core config
        self.core = CORE.copy()
        if config is None:
            config = omegaconf.OmegaConf.create({})
        # merge any custom configs
        self.core.merge_custom(config)

        # log verbosity
        if verbose:
            self.verbose = verbose
        if debug:
            self.debug = debug
        if silent:
            self.silent = silent

        # custom module directories
        self._module_dirs = set()
        self.module_dirs = module_dirs

        self.strict_scope = strict_scope

        # target / whitelist / blacklist
        from bbot.scanner.target import Target

        self.target = Target(*targets, strict_scope=self.strict_scope)
        if not whitelist:
            self.whitelist = self.target.copy()
        else:
            self.whitelist = Target(*whitelist, strict_scope=self.strict_scope)
        if not blacklist:
            blacklist = []
        self.blacklist = Target(*blacklist)

        # include other presets
        if include and not isinstance(include, (list, tuple, set)):
            include = [include]
        if include:
            for included_preset in include:
                self.include_preset(included_preset)

        # modules + flags
        if modules is None:
            modules = []
        if output_modules is None:
            output_modules = ["python", "csv", "human", "json"]
        if internal_modules is None:
            internal_modules = ["aggregate", "excavate", "speculate"]
        if isinstance(modules, str):
            modules = [modules]
        if isinstance(output_modules, str):
            output_modules = [output_modules]
        self.add_excluded_modules(exclude_modules if exclude_modules is not None else [])
        self.add_required_flags(require_flags if require_flags is not None else [])
        self.add_excluded_flags(exclude_flags if exclude_flags is not None else [])
        self.add_scan_modules(modules if modules is not None else [])
        self.add_output_modules(output_modules if output_modules is not None else [])
        self.add_internal_modules(internal_modules if internal_modules is not None else [])
        self.add_flags(flags if flags is not None else [])

    @property
    def bbot_home(self):
        return Path(self.config.get("home", "~/.bbot")).expanduser().resolve()

    @property
    def preset_dir(self):
        return self.bbot_home / "presets"

    def merge(self, other):
        # config
        self.core.merge_custom(other.core.custom_config)
        self.module_loader.core = self.core
        # module dirs
        # modules + flags
        # establish requirements / exclusions first
        self.add_excluded_modules(other.exclude_modules)
        self.add_required_flags(other.require_flags)
        self.add_excluded_flags(other.exclude_flags)
        # then it's okay to start enabling modules
        self.add_flags(other.flags)
        for module_name in other.modules:
            module_type = self.preloaded_module(module_name).get("type", "scan")
            self.add_module(module_name, module_type=module_type)
        # scope
        self.target.add_target(other.target)
        self.whitelist.add_target(other.whitelist)
        self.blacklist.add_target(other.blacklist)
        self.strict_scope = self.strict_scope or other.strict_scope
        for t in (self.target, self.whitelist):
            t.strict_scope = self.strict_scope
        # log verbosity
        if other.silent:
            self.silent = other.silent
        if other.verbose:
            self.verbose = other.verbose
        if other.debug:
            self.debug = other.debug
        # scan name
        if other.scan_name is not None:
            self.scan_name = other.scan_name
        if other.output_dir is not None:
            self.output_dir = other.output_dir
        # conditions
        if other.conditions:
            self.conditions.extend(other.conditions)
        # misc
        self.force = self.force | other.force

    def bake(self):
        """
        return a "baked" copy of the preset, ready for use by a BBOT scan
        """
        # create a copy of self
        baked_preset = copy(self)
        # copy core
        baked_preset.core = self.core.copy()
        # copy module loader
        baked_preset._module_loader = self.module_loader.copy()
        # prepare os environment
        os_environ = baked_preset.environ.prepare()
        # find and replace preloaded modules with os environ
        # this is different from the config variable substitution because it modifies
        #  the preloaded modules, i.e. their ansible playbooks
        baked_preset.module_loader.find_and_replace(**os_environ)
        # update os environ
        os.environ.clear()
        os.environ.update(os_environ)

        # evaluate conditions
        if baked_preset.conditions:
            from .conditions import ConditionEvaluator

            evaluator = ConditionEvaluator(baked_preset)
            evaluator.evaluate()

        return baked_preset

    def parse_args(self):
        self.merge(self.args.preset_from_args())

    @property
    def module_dirs(self):
        return self.module_loader.module_dirs

    @module_dirs.setter
    def module_dirs(self, module_dirs):
        if module_dirs:
            if isinstance(module_dirs, str):
                module_dirs = [module_dirs]
            for m in module_dirs:
                self.module_loader.add_module_dir(m)
                self._module_dirs.add(m)

    @property
    def modules(self):
        return self._modules

    @modules.setter
    def modules(self, modules):
        if isinstance(modules, str):
            modules = [modules]
        modules = set(modules)
        for module_name in modules:
            self.add_module(module_name)

    @property
    def scan_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "scan"]

    @scan_modules.setter
    def scan_modules(self, modules):
        self.log_debug(f"Setting scan modules to {modules}")
        self._modules_setter(modules, module_type="scan")

    @property
    def output_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "output"]

    @output_modules.setter
    def output_modules(self, modules):
        self.log_debug(f"Setting output modules to {modules}")
        self._modules_setter(modules, module_type="output")

    @property
    def internal_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "internal"]

    @internal_modules.setter
    def internal_modules(self, modules):
        self.log_debug(f"Setting internal modules to {modules}")
        self._modules_setter(modules, module_type="internal")

    def _modules_setter(self, modules, module_type="scan"):
        if isinstance(modules, str):
            modules = [modules]
        # start by removing currently-enabled modules of that type
        for module_name in list(self.modules):
            if module_type and self.preloaded_module(module_name).get("type", "scan") == module_type:
                self._modules.remove(module_name)
        for module_name in set(modules):
            self.add_module(module_name, module_type=module_type)

    def add_scan_modules(self, modules):
        for module in modules:
            self.add_module(module, module_type="scan")

    def add_output_modules(self, modules):
        for module in modules:
            self.add_module(module, module_type="output")

    def add_internal_modules(self, modules):
        for module in modules:
            self.add_module(module, module_type="internal")

    def add_module(self, module_name, module_type="scan"):
        # log.info(f'Adding "{module_name}": {module_type}')
        if module_name in self.exclude_modules:
            self.log_verbose(f'Skipping module "{module_name}" because it\'s excluded')
            return
        try:
            preloaded = self.module_loader.preloaded()[module_name]
        except KeyError:
            raise EnableModuleError(f'Unable to add unknown BBOT module "{module_name}"')

        module_flags = preloaded.get("flags", [])
        _module_type = preloaded.get("type", "scan")
        if module_type:
            if _module_type != module_type:
                self.log_verbose(
                    f'Not adding module "{module_name}" because its type ({_module_type}) is not "{module_type}"'
                )
                return

        if _module_type == "scan":
            for f in module_flags:
                if f in self.exclude_flags:
                    self.log_verbose(f'Skipping module "{module_name}" because it\'s excluded')
                    return
            if self.require_flags and not any(f in self.require_flags for f in module_flags):
                self.log_verbose(
                    f'Skipping module "{module_name}" because it doesn\'t have the required flags ({",".join(self.require_flags)})'
                )
                return

        if module_name not in self.modules:
            self.log_verbose(f'Adding module "{module_name}"')
            self.modules.add(module_name)
            for module_dep in preloaded.get("deps", {}).get("modules", []):
                if module_dep not in self.modules:
                    self.log_verbose(f'Adding module "{module_dep}" because {module_name} depends on it')
                    self.add_module(module_dep)

    @property
    def exclude_modules(self):
        return self._exclude_modules

    @property
    def exclude_flags(self):
        return self._exclude_flags

    @property
    def require_flags(self):
        return self._require_flags

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, flags):
        self.log_debug(f"Setting flags to {flags}")
        self._flags = set(flags)
        for flag in flags:
            self.add_flag(flag)

    def add_flags(self, flags):
        for flag in flags:
            self.add_flag(flag)

    def add_flag(self, flag):
        if not flag in self.module_loader._all_flags:
            raise EnableFlagError(f'Flag "{flag}" was not found')
        for module, preloaded in self.module_loader.preloaded().items():
            module_flags = preloaded.get("flags", [])
            if flag in module_flags:
                self.add_module(module)

    @require_flags.setter
    def require_flags(self, flags):
        self.log_debug(f"Setting required flags to {flags}")
        if isinstance(flags, str):
            flags = [flags]
        self._require_flags = set()
        for flag in set(flags):
            self.require_flag(flag)

    @exclude_modules.setter
    def exclude_modules(self, modules):
        self.log_debug(f"Setting excluded modules to {modules}")
        if isinstance(modules, str):
            modules = [modules]
        self._exclude_modules = set()
        for module in set(modules):
            self.exclude_module(module)

    @exclude_flags.setter
    def exclude_flags(self, flags):
        self.log_debug(f"Setting excluded flags to {flags}")
        if isinstance(flags, str):
            flags = [flags]
        self._exclude_flags = set()
        for flag in set(flags):
            self.exclude_flag(flag)

    def add_required_flags(self, flags):
        for flag in flags:
            self.require_flag(flag)

    def require_flag(self, flag):
        self.require_flags.add(flag)
        for module in list(self.scan_modules):
            module_flags = self.preloaded_module(module).get("flags", [])
            if flag not in module_flags:
                self.log_verbose(f'Removing module "{module}" because it doesn\'t have the required flag, "{flag}"')
                self.modules.remove(module)

    def add_excluded_flags(self, flags):
        for flag in flags:
            self.exclude_flag(flag)

    def exclude_flag(self, flag):
        self.exclude_flags.add(flag)
        for module in list(self.scan_modules):
            module_flags = self.preloaded_module(module).get("flags", [])
            if flag in module_flags:
                self.log_verbose(f'Removing module "{module}" because it has the excluded flag, "{flag}"')
                self.modules.remove(module)

    def add_excluded_modules(self, modules):
        for module in modules:
            self.exclude_module(module)

    def exclude_module(self, module):
        self.exclude_modules.add(module)
        for module in list(self.scan_modules):
            if module in self.exclude_modules:
                self.log_verbose(f'Removing module "{module}" because it\'s excluded')
                self.modules.remove(module)

    def preloaded_module(self, module):
        return self.module_loader.preloaded()[module]

    @property
    def config(self):
        return self.core.config

    @property
    def verbose(self):
        return self._verbose

    @verbose.setter
    def verbose(self, value):
        if value:
            self._debug = False
            self._silent = False
            self.core.merge_custom({"verbose": True})
            self.core.logger.log_level = "VERBOSE"
        else:
            with suppress(omegaconf.errors.ConfigKeyError):
                del self.core.custom_config["verbose"]
            self.core.logger.log_level = "INFO"
        self._verbose = value

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, value):
        if value:
            self._verbose = False
            self._silent = False
            self.core.merge_custom({"debug": True})
            self.core.logger.log_level = "DEBUG"
        else:
            with suppress(omegaconf.errors.ConfigKeyError):
                del self.core.custom_config["debug"]
            self.core.logger.log_level = "INFO"
        self._debug = value

    @property
    def silent(self):
        return self._silent

    @silent.setter
    def silent(self, value):
        if value:
            self._verbose = False
            self._debug = False
            self.core.merge_custom({"silent": True})
            self.core.logger.log_level = "CRITICAL"
        else:
            with suppress(omegaconf.errors.ConfigKeyError):
                del self.core.custom_config["silent"]
            self.core.logger.log_level = "INFO"
        self._silent = value

    @property
    def helpers(self):
        if self._helpers is None:
            from bbot.core.helpers.helper import ConfigAwareHelper

            self._helpers = ConfigAwareHelper(preset=self)
        return self._helpers

    @property
    def module_loader(self):
        self.environ
        if self._module_loader is None:
            from bbot.core.modules import module_loader

            self._module_loader = module_loader

        return self._module_loader

    @property
    def environ(self):
        if self._environ is None:
            from .environ import BBOTEnviron

            self._environ = BBOTEnviron(self)
        return self._environ

    @property
    def args(self):
        if self._args is None:
            from .args import BBOTArgs

            self._args = BBOTArgs(self)
        return self._args

    def in_scope(self, e):
        """
        Check whether a hostname, url, IP, etc. is in scope.
        Accepts either events or string data.

        Checks whitelist and blacklist.
        If `e` is an event and its scope distance is zero, it will be considered in-scope.

        Examples:
            Check if a URL is in scope:
            >>> preset.in_scope("http://www.evilcorp.com")
            True
        """
        try:
            e = make_event(e, dummy=True)
        except ValidationError:
            return False
        in_scope = e.scope_distance == 0 or self.whitelisted(e)
        return in_scope and not self.blacklisted(e)

    def blacklisted(self, e):
        """
        Check whether a hostname, url, IP, etc. is blacklisted.
        """
        e = make_event(e, dummy=True)
        return e in self.blacklist

    def whitelisted(self, e):
        """
        Check whether a hostname, url, IP, etc. is whitelisted.
        """
        e = make_event(e, dummy=True)
        return e in self.whitelist

    @classmethod
    def from_dict(cls, preset_dict, name=None, _exclude=None, _log=False):
        new_preset = cls(
            *preset_dict.get("target", []),
            whitelist=preset_dict.get("whitelist"),
            blacklist=preset_dict.get("blacklist"),
            modules=preset_dict.get("modules"),
            output_modules=preset_dict.get("output_modules"),
            exclude_modules=preset_dict.get("exclude_modules"),
            flags=preset_dict.get("flags"),
            require_flags=preset_dict.get("require_flags"),
            exclude_flags=preset_dict.get("exclude_flags"),
            verbose=preset_dict.get("verbose", False),
            debug=preset_dict.get("debug", False),
            silent=preset_dict.get("silent", False),
            config=preset_dict.get("config"),
            strict_scope=preset_dict.get("strict_scope", False),
            module_dirs=preset_dict.get("module_dirs", []),
            include=list(preset_dict.get("include", [])),
            scan_name=preset_dict.get("scan_name"),
            output_dir=preset_dict.get("output_dir"),
            name=preset_dict.get("name", name),
            description=preset_dict.get("description"),
            conditions=preset_dict.get("conditions", []),
            _exclude=_exclude,
            _log=_log,
        )
        return new_preset

    def include_preset(self, filename):
        self.log_debug(f'Including preset "{filename}"')
        preset_filename = PRESET_PATH.find(filename)
        preset_from_yaml = self.from_yaml_file(preset_filename, _exclude=self._preset_files_loaded)
        if preset_from_yaml is not False:
            self.merge(preset_from_yaml)
        self._preset_files_loaded.add(preset_filename)

    @classmethod
    def from_yaml_file(cls, filename, _exclude=None, _log=False):
        """
        Create a preset from a YAML file. If the full path is not specified, BBOT will look in all the usual places for it.

        The file extension is optional.
        """
        if _exclude is None:
            _exclude = set()
        filename = Path(filename).resolve()
        if _exclude is not None and filename in _exclude:
            log.debug(f"Not loading {filename} because it was already loaded {_exclude}")
            return False
        log.debug(f"Loading {filename} because it's not in excluded list ({_exclude})")
        _exclude = set(_exclude)
        _exclude.add(filename)
        try:
            yaml_str = open(filename).read()
        except FileNotFoundError:
            raise PresetNotFoundError(f'Could not find preset at "{filename}" - file does not exist')
        preset = cls.from_dict(omegaconf.OmegaConf.create(yaml_str), name=filename.stem, _exclude=_exclude, _log=_log)
        preset._yaml_str = yaml_str
        return preset

    @classmethod
    def from_yaml_string(cls, yaml_preset):
        return cls.from_dict(omegaconf.OmegaConf.create(yaml_preset))

    def to_dict(self, include_target=False, full_config=False):
        preset_dict = {}

        # config
        if full_config:
            config = self.core.config
        else:
            config = self.core.custom_config
        config = omegaconf.OmegaConf.to_container(config)
        if config:
            preset_dict["config"] = config

        # scope
        if include_target:
            target = sorted(str(t.data) for t in self.target)
            whitelist = sorted(str(t.data) for t in self.whitelist)
            blacklist = sorted(str(t.data) for t in self.blacklist)
            if target:
                preset_dict["target"] = target
            if whitelist and whitelist != target:
                preset_dict["whitelist"] = whitelist
            if blacklist:
                preset_dict["blacklist"] = blacklist
        if self.strict_scope:
            preset_dict["strict_scope"] = True

        # flags + modules
        if self.require_flags:
            preset_dict["require_flags"] = sorted(self.require_flags)
        if self.exclude_flags:
            preset_dict["exclude_flags"] = sorted(self.exclude_flags)
        if self.exclude_modules:
            preset_dict["exclude_modules"] = sorted(self.exclude_modules)
        if self.flags:
            preset_dict["flags"] = sorted(self.flags)
        scan_modules = self.scan_modules
        output_modules = self.output_modules
        if scan_modules:
            preset_dict["modules"] = sorted(scan_modules)
        if output_modules:
            preset_dict["output_modules"] = sorted(output_modules)

        # log verbosity
        if self.verbose:
            preset_dict["verbose"] = True
        if self.debug:
            preset_dict["debug"] = True
        if self.silent:
            preset_dict["silent"] = True

        # misc scan options
        if self.scan_name:
            preset_dict["scan_name"] = self.scan_name
        if self.scan_name:
            preset_dict["output_dir"] = self.output_dir

        # conditions
        if self.conditions:
            preset_dict["conditions"] = [c[-1] for c in self.conditions]

        return preset_dict

    def to_yaml(self, include_target=False, full_config=False, sort_keys=False):
        preset_dict = self.to_dict(include_target=include_target, full_config=full_config)
        return yaml.dump(preset_dict, sort_keys=sort_keys)

    def all_presets(self):
        preset_dir = self.preset_dir
        home_dir = Path.home()

        # first, add local preset dir to PRESET_PATH
        PRESET_PATH.add_path(self.preset_dir)

        # ensure local preset directory exists
        mkdir(preset_dir)

        global DEFAULT_PRESETS
        if DEFAULT_PRESETS is None:
            presets = dict()
            for ext in ("yml", "yaml"):
                for preset_path in PRESET_PATH:
                    # for every yaml file
                    for original_filename in preset_path.rglob(f"**/*.{ext}"):
                        # not including symlinks
                        if original_filename.is_symlink():
                            continue

                        # try to load it as a preset
                        try:
                            loaded_preset = self.from_yaml_file(original_filename, _log=True)
                        except Exception as e:
                            log.warning(f'Failed to load preset at "{original_filename}": {e}')
                            log.trace(traceback.format_exc())
                            continue

                        # category is the parent folder(s), if any
                        category = str(original_filename.relative_to(preset_path).parent)
                        if category == ".":
                            category = ""

                        local_preset = original_filename
                        # populate symlinks in local preset dir
                        if not original_filename.is_relative_to(preset_dir):
                            relative_preset = original_filename.relative_to(preset_path)
                            local_preset = preset_dir / relative_preset
                            mkdir(local_preset.parent, check_writable=False)
                            if not local_preset.exists():
                                local_preset.symlink_to(original_filename)

                        if local_preset.is_relative_to(home_dir):
                            local_preset = Path("~") / local_preset.relative_to(home_dir)

                        presets[local_preset] = (loaded_preset, category, preset_path, original_filename)

            # sort by name
            DEFAULT_PRESETS = dict(sorted(presets.items(), key=lambda x: x[-1][0].name))
        return DEFAULT_PRESETS

    def presets_table(self, include_modules=True):
        table = []
        header = ["Preset", "Category", "Description", "# Modules"]
        if include_modules:
            header.append("Modules")
        for yaml_file, (loaded_preset, category, preset_path, original_file) in self.all_presets().items():
            num_modules = f"{len(loaded_preset.scan_modules):,}"
            row = [loaded_preset.name, category, loaded_preset.description, num_modules]
            if include_modules:
                row.append(", ".join(sorted(loaded_preset.scan_modules)))
            table.append(row)
        return make_table(table, header)

    def log_verbose(self, msg):
        if self._log:
            log.verbose(f"Preset {self.name}: {msg}")

    def log_debug(self, msg):
        if self._log:
            log.debug(f"Preset {self.name}: {msg}")
