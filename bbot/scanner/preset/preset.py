import yaml
import logging
import omegaconf
from pathlib import Path
from contextlib import suppress

from bbot.core import CORE
from bbot.core.event.base import make_event
from bbot.core.errors import ValidationError


log = logging.getLogger("bbot.presets")

bbot_code_dir = Path(__file__).parent.parent.parent


class Preset:

    default_module_dir = bbot_code_dir / "modules"

    def __init__(
        self,
        *targets,
        whitelist=None,
        blacklist=None,
        modules=None,
        output_modules=None,
        exclude_modules=None,
        flags=None,
        require_flags=None,
        exclude_flags=None,
        verbose=False,
        debug=False,
        silent=False,
        config=None,
        strict_scope=False,
    ):
        self._args = None
        self._environ = None
        self._helpers = None
        self._module_loader = None

        self._modules = set()

        self._exclude_modules = set()
        self._require_flags = set()
        self._exclude_flags = set()
        self._flags = set()

        self._verbose = False
        self._debug = False
        self._silent = False

        # bbot core config
        self.core = CORE.copy()
        if config is None:
            config = omegaconf.OmegaConf.create({})
        # merge any custom configs
        self.core.merge_custom(config)

        # dirs to load modules from
        self.module_dirs = self.core.config.get("module_dirs", [])
        self.module_dirs = [Path(p) for p in self.module_dirs] + [self.default_module_dir]
        self.module_dirs = set(self.module_dirs)

        # modules
        if modules is None:
            modules = []
        if output_modules is None:
            output_modules = ["python"]
        if isinstance(modules, str):
            modules = [modules]
        if isinstance(output_modules, str):
            output_modules = [output_modules]
        self.modules = set(modules if modules is not None else [])
        for output_module in set(output_modules if output_modules is not None else []):
            self.add_module(output_module)
        self.exclude_modules = set(exclude_modules if exclude_modules is not None else [])

        # module flags
        self.flags = set(flags if flags is not None else [])
        self.require_flags = set(require_flags if require_flags is not None else [])
        self.exclude_flags = set(exclude_flags if exclude_flags is not None else [])

        # PRESET TODO: preparation of environment
        # self.core.environ.prepare()

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

        # log verbosity
        if verbose:
            self.verbose = verbose
        if debug:
            self.debug = debug
        if silent:
            self.silent = silent

        self.bbot_home = Path(self.config.get("home", "~/.bbot")).expanduser().resolve()

    def merge(self, other):
        # module dirs
        current_module_dirs = set(self.module_dirs)
        other_module_dirs = set(other.module_dirs)
        combined_module_dirs = current_module_dirs.union(other_module_dirs)
        if combined_module_dirs != current_module_dirs:
            self.module_dirs = combined_module_dirs
            # TODO: refresh module dirs
        # modules + flags
        self.exclude_modules = set(self.exclude_modules).union(set(other.exclude_modules))
        self.require_flags = set(self.require_flags).union(set(other.require_flags))
        self.exclude_flags = set(self.exclude_flags).union(set(other.exclude_flags))
        self.flags = set(self.flags).union(set(other.flags))
        for module_name in other.modules:
            self.add_module(module_name)
        # scope
        self.target.add_target(other.target)
        self.whitelist = other.whitelist
        self.blacklist.add_target(other.blacklist)
        self.strict_scope = self.strict_scope or other.strict_scope
        for t in (self.target, self.whitelist):
            t.strict_scope = self.strict_scope
        # config
        self.core.merge_custom(other.core.custom_config)
        # log verbosity
        self.silent = other.silent
        self.verbose = other.verbose
        self.debug = other.debug

    def parse_args(self):

        from .args import BBOTArgs

        self._args = BBOTArgs(self)
        self.merge(self.args.preset_from_args())

        # bring in presets
        # self.merge(self.args.presets)

        # bring in config
        # self.core.merge_custom(self.args.config)

        # bring in misc cli arguments

        # validate config / modules / flags
        # self.args.validate()

    @property
    def scan_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "scan"]

    @property
    def output_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "output"]

    @property
    def internal_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "internal"]

    @property
    def modules(self):
        return self._modules

    @modules.setter
    def modules(self, modules):
        modules = set(modules)
        for module_name in modules:
            self.add_module(module_name)

    def add_module(self, module_name):
        if module_name in self.exclude_modules:
            log.verbose(f'Skipping module "{module_name}" because it\'s excluded')
            return
        try:
            preloaded = self.module_loader.preloaded()[module_name]
        except KeyError:
            raise KeyError(f'Unable to add unknown module "{module_name}": {e}')

        module_flags = preloaded.get("flags", [])
        for f in module_flags:
            if f in self.exclude_flags:
                log.verbose(f'Skipping module "{module_name}" because it\'s excluded')
                return
            if self.require_flags and f not in self.require_flags:
                log.verbose(f'Skipping module "{module_name}" because it doesn\'t have the required flags')
                return

        if module_name not in self.modules:
            log.verbose(f'Enabling module "{module_name}"')
            self.modules.add(module_name)
            for module_dep in preloaded.get("deps", {}).get("modules", []):
                if module_dep not in self.modules:
                    log.verbose(f'Enabling module "{module_dep}" because {module_name} depends on it')
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
        self._flags = set()
        for module, preloaded in self.module_loader.preloaded().items():
            module_flags = preloaded.get("flags", [])
            if any(f in module_flags for f in module_flags):
                self.add_module(module)

    @require_flags.setter    
    def require_flags(self, flags):
        self._require_flags = set()
        for flag in flags:
            self.add_required_flag(flag)

    @exclude_modules.setter
    def exclude_modules(self, modules):
        self._exclude_modules = set()
        for module in modules:
            self.add_excluded_module(module)

    @exclude_flags.setter
    def exclude_flags(self, flags):
        self._exclude_flags = set()
        for flag in flags:
            self.add_excluded_flag(flag)

    def add_required_flag(self, flag):
        self.require_flags.add(flag)
        for module in list(self.modules):
            module_flags = self.preloaded_module(module).get("flags", [])
            if flag not in module_flags:
                log.verbose(f'Removing module "{module}" because it doesn\'t have the required flag, "{flag}"')
                self.modules.remove(module)

    def add_excluded_flag(self, flag):
        self.exclude_flags.add(flag)
        for module in list(self.modules):
            module_flags = self.preloaded_module(module).get("flags", [])
            if flag in module_flags:
                log.verbose(f'Removing module "{module}" because it has the excluded flag, "{flag}"')
                self.modules.remove(module)

    def add_excluded_module(self, module):
        self.exclude_modules.add(module)
        for module in list(self.modules):
            if module in self.exclude_modules:
                log.verbose(f'Removing module "{module}" because is excluded')
                self.modules.remove(module)

    def preloaded_module(self, module):
        return self.module_loader.preloaded()[module]

    @property
    def config(self):
        return self.core.config

    @property
    def verbose(self):
        return self._verbose

    @property
    def debug(self):
        return self._debug

    @property
    def silent(self):
        return self._silent

    @verbose.setter
    def verbose(self, value):
        if value:
            self.debug = False
            self.silent = False
            self.core.merge_custom({"verbose": True})
            self.core.logger.log_level = "VERBOSE"
        else:
            with suppress(omegaconf.errors.ConfigKeyError):
                del self.core.custom_config["verbose"]
            self.core.logger.log_level = "INFO"
        self._verbose = value

    @debug.setter
    def debug(self, value):
        if value:
            self.verbose = False
            self.silent = False
            self.core.merge_custom({"debug": True})
            self.core.logger.log_level = "DEBUG"
        else:
            with suppress(omegaconf.errors.ConfigKeyError):
                del self.core.custom_config["debug"]
            self.core.logger.log_level = "INFO"
        self._debug = value

    @silent.setter
    def silent(self, value):
        if value:
            self.verbose = False
            self.debug = False
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
        # module loader depends on environment to be set up
        # or is it the other way around
        # PRESET TODO
        self.environ
        if self._module_loader is None:
            from bbot.core.modules import ModuleLoader

            self._module_loader = ModuleLoader(self)

            # update default config with module defaults
            module_config = omegaconf.OmegaConf.create(
                {
                    "modules": self._module_loader.configs(type="scan"),
                    "output_modules": self._module_loader.configs(type="output"),
                    "internal_modules": self._module_loader.configs(type="internal"),
                }
            )
            self.core.merge_default(module_config)

        return self._module_loader

    @property
    def internal_modules(self):
        return list(self.module_loader.preloaded(type="internal"))

    @property
    def environ(self):
        if self._environ is None:
            from .environ import BBOTEnviron

            self._environ = BBOTEnviron(self)
        return self._environ

    @property
    def args(self):
        return self._args

    def in_scope(self, e):
        """
        Check whether a hostname, url, IP, etc. is in scope.
        Accepts either events or string data.

        Checks whitelist and blacklist.
        If `e` is an event and its scope distance is zero, it will be considered in-scope.

        Examples:
            Check if a URL is in scope:
            >>> scan.in_scope("http://www.evilcorp.com")
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
    def from_dict(cls, preset_dict):
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
        )
        return new_preset
    
    @classmethod
    def from_yaml_file(cls, yaml_preset):
        return cls.from_dict(omegaconf.OmegaConf.load(yaml_preset))

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
        # establish requirements / exclusions first
        if self.require_flags:
            preset_dict["require_flags"] = sorted(self.require_flags)
        if self.exclude_flags:
            preset_dict["exclude_flags"] = sorted(self.exclude_flags)
        if self.exclude_modules:
            preset_dict["exclude_modules"] = sorted(self.exclude_modules)
        # then it's okay to start enabling modules
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

        return preset_dict

    def to_yaml(self, include_target=False, full_config=False, sort_keys=False):
        preset_dict = self.to_dict(include_target=include_target, full_config=full_config)
        return yaml.dump(preset_dict, sort_keys=sort_keys)
