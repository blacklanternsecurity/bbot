import yaml
from copy import copy
from pathlib import Path
from omegaconf import OmegaConf

from bbot.core import CORE
from bbot.core.event.base import make_event
from bbot.core.errors import ValidationError


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

        # bbot core config
        self.core = copy(CORE)
        if config is None:
            config = OmegaConf.create({})
        # merge any custom configs
        self.core.merge_custom(config)

        # modules
        if modules is None:
            modules = []
        if output_modules is None:
            output_modules = ["python"]
        if isinstance(modules, str):
            modules = [modules]
        if isinstance(output_modules, str):
            output_modules = [output_modules]
        self.scan_modules = set(modules if modules is not None else [])
        self.output_modules = set(output_modules if output_modules is not None else [])
        self.exclude_modules = set(exclude_modules if exclude_modules is not None else [])

        # module flags
        self.flags = set(flags if flags is not None else [])
        self.require_flags = set(require_flags if require_flags is not None else [])
        self.exclude_flags = set(exclude_flags if exclude_flags is not None else [])

        # PRESET TODO: preparation of environment
        # self.core.environ.prepare()
        if self.core.config.get("debug", False):
            self.core.logger.set_log_level("DEBUG")

        # dirs to load modules from
        self.module_dirs = self.core.config.get("module_dirs", [])
        self.module_dirs = [Path(p) for p in self.module_dirs] + [self.default_module_dir]
        self.module_dirs = set(self.module_dirs)

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
        self._verbose = verbose
        self._debug = debug
        self._silent = silent

        self.bbot_home = Path(self.config.get("home", "~/.bbot")).expanduser().resolve()

    def merge(self, other):
        # module dirs
        current_module_dirs = set(self.module_dirs)
        other_module_dirs = set(other.module_dirs)
        combined_module_dirs = current_module_dirs.union(other_module_dirs)
        if combined_module_dirs != current_module_dirs:
            self.module_dirs = combined_module_dirs
            # TODO: refresh module dirs
        # modules
        self.scan_modules = set(self.scan_modules).union(set(other.scan_modules))
        self.output_modules = set(self.output_modules).union(set(other.output_modules))
        self.exclude_modules = set(self.exclude_modules).union(set(other.exclude_modules))
        # flags
        self.flags = set(self.flags).union(set(other.flags))
        self.require_flags = set(self.require_flags).union(set(other.require_flags))
        self.exclude_flags = set(self.exclude_flags).union(set(other.exclude_flags))
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
            self.core.logger.set_log_level("VERBOSE")
        else:
            self.core.del_config_item("verbose")
            self.core.logger.set_log_level("INFO")

    @debug.setter
    def debug(self, value):
        if value:
            self.verbose = False
            self.silent = False
            self.core.merge_custom({"debug": True})
            self.core.logger.set_log_level("DEBUG")
        else:
            self.core.del_config_item("debug")
            self.core.logger.set_log_level("INFO")

    @silent.setter
    def silent(self, value):
        if value:
            self.verbose = False
            self.debug = False
            self.core.merge_custom({"silent": True})
            self.core.logger.set_log_level("CRITICAL")
        else:
            self.core.del_config_item("silent")
            self.core.logger.set_log_level("INFO")

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
            module_config = OmegaConf.create(
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
    def all_modules(self):
        return sorted(self.scan_modules.union(self.output_modules).union(self.internal_modules))

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
    def from_yaml(cls, yaml_preset):
        if Path(yaml_preset).is_file():
            preset_dict = OmegaConf.load(yaml_preset)
        else:
            preset_dict = OmegaConf.create(yaml_preset)
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

    def to_dict(self, include_target=False, full_config=False):
        preset_dict = {}

        # config
        if full_config:
            config = self.core.config
        else:
            config = self.core.custom_config
        config = OmegaConf.to_container(config)
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

        # modules
        if self.scan_modules:
            preset_dict["modules"] = sorted(self.scan_modules)
        if self.output_modules:
            preset_dict["output_modules"] = sorted(self.output_modules)
        if self.exclude_modules:
            preset_dict["exclude_modules"] = sorted(self.exclude_modules)

        # flags
        if self.flags:
            preset_dict["flags"] = sorted(self.flags)
        if self.require_flags:
            preset_dict["require_flags"] = sorted(self.require_flags)
        if self.exclude_flags:
            preset_dict["exclude_flags"] = sorted(self.exclude_flags)

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
