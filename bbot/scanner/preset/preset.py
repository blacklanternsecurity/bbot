import os
import yaml
import logging
import omegaconf
import traceback
from copy import copy
from pathlib import Path
from contextlib import suppress

from .path import PRESET_PATH

from bbot.errors import *
from bbot.core import CORE
from bbot.core.helpers.misc import make_table, mkdir, get_closest_match


log = logging.getLogger("bbot.presets")


_preset_cache = dict()


# cache default presets to prevent having to reload from disk
DEFAULT_PRESETS = None


class Preset:
    """
    A preset is the central config for a BBOT scan. It contains everything a scan needs to run --
        targets, modules, flags, config options like API keys, etc.

    You can create a preset manually and pass it into `Scanner(preset=preset)`.
        Or, you can pass `Preset`'s kwargs into `Scanner()` and it will create the preset for you implicitly.

    Presets can include other presets (which can in turn include other presets, and so on).
        This works by merging each preset in turn using `Preset.merge()`.
        The order matters. In case of a conflict, the last preset to be merged wins priority.

    Presets can be loaded from or saved to YAML. BBOT has a number of ready-made presets for common tasks like
    subdomain enumeration, web spidering, dirbusting, etc.

    Presets are highly customizable via `conditions`, which use the Jinja2 templating engine.
        Using `conditions`, you can define custom logic to inspect the final preset before the scan starts, and change it if need be.
        Based on the state of the preset, you can print a warning message, abort the scan, enable/disable modules, etc..

    Attributes:
        target (Target): Target(s) of scan.
        whitelist (Target): Scan whitelist (by default this is the same as `target`).
        blacklist (Target): Scan blacklist (this takes ultimate precedence).
        strict_scope (bool): If True, subdomains of targets are not considered to be in-scope.
        helpers (ConfigAwareHelper): Helper containing various reusable functions, regexes, etc.
        output_dir (pathlib.Path): Output directory for scan.
        scan_name (str): Name of scan. Defaults to random value, e.g. "demonic_jimmy".
        name (str): Human-friendly name of preset. Used mainly for logging purposes.
        description (str): Description of preset.
        modules (set): Combined modules to enable for the scan. Includes scan modules, internal modules, and output modules.
        scan_modules (set): Modules to enable for the scan.
        output_modules (set): Output modules to enable for the scan. (note: if no output modules are specified, this is not populated until .bake())
        internal_modules (set): Internal modules for the scan. (note: not populated until .bake())
        exclude_modules (set): Modules to exclude from the scan. When set, automatically removes excluded modules.
        flags (set): Flags to enable for the scan. When set, automatically enables modules.
        require_flags (set): Require modules to have these flags. When set, automatically removes offending modules.
        exclude_flags (set): Exclude modules that have any of these flags. When set, automatically removes offending modules.
        module_dirs (set): Custom directories from which to load modules (alias to `self.module_loader.module_dirs`). When set, automatically preloads contained modules.
        config (omegaconf.dictconfig.DictConfig): BBOT config (alias to `core.config`)
        core (BBOTCore): Local copy of BBOTCore object.
        verbose (bool): Whether log level is currently set to verbose. When set, updates log level for all BBOT log handlers.
        debug (bool): Whether log level is currently set to debug. When set, updates log level for all BBOT log handlers.
        silent (bool): Whether logging is currently disabled. When set to True, silences all stderr.

    Examples:
        >>> preset = Preset(
                "evilcorp.com",
                "1.2.3.0/24",
                flags=["subdomain-enum"],
                modules=["nuclei"],
                config={"web": {"http_proxy": "http://127.0.0.1"}}
            )
        >>> scan = Scanner(preset=preset)

        >>> preset = Preset.from_yaml_file("my_preset.yml")
        >>> scan = Scanner(preset=preset)
    """

    def __init__(
        self,
        *targets,
        whitelist=None,
        blacklist=None,
        strict_scope=False,
        modules=None,
        output_modules=None,
        exclude_modules=None,
        flags=None,
        require_flags=None,
        exclude_flags=None,
        config=None,
        module_dirs=None,
        include=None,
        presets=None,
        output_dir=None,
        scan_name=None,
        name=None,
        description=None,
        conditions=None,
        force_start=False,
        verbose=False,
        debug=False,
        silent=False,
        _exclude=None,
        _log=True,
    ):
        """
        Initializes the Preset class.

        Args:
            *targets (str): Target(s) to scan. Types supported: hostnames, IPs, CIDRs, emails, open ports.
            whitelist (list, optional): Whitelisted target(s) to scan. Defaults to the same as `targets`.
            blacklist (list, optional): Blacklisted target(s). Takes ultimate precedence. Defaults to empty.
            strict_scope (bool, optional): If True, subdomains of targets are not in-scope.
            modules (list[str], optional): List of scan modules to enable for the scan. Defaults to empty list.
            output_modules (list[str], optional): List of output modules to use. Defaults to csv, human, and json.
            exclude_modules (list[str], optional): List of modules to exclude from the scan.
            require_flags (list[str], optional): Only enable modules if they have these flags.
            exclude_flags (list[str], optional): Don't enable modules if they have any of these flags.
            module_dirs (list[str], optional): additional directories to load modules from.
            config (dict, optional): Additional scan configuration settings.
            include (list[str], optional): names or filenames of other presets to include.
            presets (list[str], optional): an alias for `include`.
            output_dir (str or Path, optional): Directory to store scan output. Defaults to BBOT home directory (`~/.bbot`).
            scan_name (str, optional): Human-readable name of the scan. If not specified, it will be random, e.g. "demonic_jimmy".
            name (str, optional): Human-readable name of the preset. Used mainly for logging.
            description (str, optional): Description of the preset.
            conditions (list[str], optional): Custom conditions to be executed before scan start. Written in Jinja2.
            force_start (bool, optional): If True, ignore conditional aborts and failed module setups. Just run the scan!
            verbose (bool, optional): Set the BBOT logger to verbose mode.
            debug (bool, optional): Set the BBOT logger to debug mode.
            silent (bool, optional): Silence all stderr (effectively disables the BBOT logger).
            _exclude (list[Path], optional): Preset filenames to exclude from inclusion. Used internally to prevent infinite recursion in circular or self-referencing presets.
            _log (bool, optional): Whether to enable logging for the preset. This will record which modules/flags are enabled, etc.
        """
        # internal variables
        self._cli = False
        self._log = _log
        self.scan = None
        self._args = None
        self._environ = None
        self._helpers = None
        self._module_loader = None
        self._yaml_str = ""
        self._baked = False

        self._default_output_modules = None
        self._default_internal_modules = None

        # modules / flags
        self.modules = set()
        self.exclude_modules = set()
        self.flags = set()
        self.exclude_flags = set()
        self.require_flags = set()

        # modules + flags
        if modules is None:
            modules = []
        if isinstance(modules, str):
            modules = [modules]
        if output_modules is None:
            output_modules = []
        if isinstance(output_modules, str):
            output_modules = [output_modules]
        if exclude_modules is None:
            exclude_modules = []
        if isinstance(exclude_modules, str):
            exclude_modules = [exclude_modules]
        if flags is None:
            flags = []
        if isinstance(flags, str):
            flags = [flags]
        if exclude_flags is None:
            exclude_flags = []
        if isinstance(exclude_flags, str):
            exclude_flags = [exclude_flags]
        if require_flags is None:
            require_flags = []
        if isinstance(require_flags, str):
            require_flags = [require_flags]

        # these are used only for preserving the modules as specified in the original preset
        # this is to ensure the preset looks the same when reserialized
        self.explicit_scan_modules = set() if modules is None else set(modules)
        self.explicit_output_modules = set() if output_modules is None else set(output_modules)

        # whether to force-start the scan (ignoring conditional aborts and failed module setups)
        self.force_start = force_start

        # scan output directory
        self.output_dir = output_dir
        # name of scan
        self.scan_name = scan_name

        # name of preset, default blank
        self.name = name or ""
        # preset description, default blank
        self.description = description or ""

        # custom conditions, evaluated during .bake()
        self.conditions = []
        if conditions is not None:
            for condition in conditions:
                self.conditions.append((self.name, condition))

        # keeps track of loaded preset files to prevent infinite circular inclusions
        self._preset_files_loaded = set()
        if _exclude is not None:
            for _filename in _exclude:
                self._preset_files_loaded.add(Path(_filename).resolve())

        # bbot core config
        self.core = CORE.copy()
        if config is None:
            config = omegaconf.OmegaConf.create({})
        # merge custom configs if specified by the user
        self.core.merge_custom(config)

        # log verbosity
        # actual log verbosity isn't set until .bake()
        self.verbose = verbose
        self.debug = debug
        self.silent = silent

        # custom module directories
        self._module_dirs = set()
        self.module_dirs = module_dirs

        # target / whitelist / blacklist
        self.strict_scope = strict_scope
        # these are temporary receptacles until they all get .baked() together
        self._seeds = set(targets if targets else [])
        self._whitelist = set(whitelist) if whitelist else whitelist
        self._blacklist = set(blacklist if blacklist else [])

        self._target = None

        # "presets" is alias to "include"
        if presets and include:
            raise ValueError(
                'Cannot use both "presets" and "include" args at the same time (presets is only an alias to include). Please pick only one :)'
            )
        if presets and not include:
            include = presets
        # include other presets
        if include and not isinstance(include, (list, tuple, set)):
            include = [include]
        if include:
            for included_preset in include:
                self.include_preset(included_preset)

        # we don't fill self.modules yet (that happens in .bake())
        self.explicit_scan_modules.update(set(modules))
        self.explicit_output_modules.update(set(output_modules))
        self.exclude_modules.update(set(exclude_modules))
        self.flags.update(set(flags))
        self.exclude_flags.update(set(exclude_flags))
        self.require_flags.update(set(require_flags))

    @property
    def bbot_home(self):
        return Path(self.config.get("home", "~/.bbot")).expanduser().resolve()

    @property
    def target(self):
        if self._target is None:
            raise ValueError("Cannot access target before preset is baked (use ._seeds instead)")
        return self._target

    @property
    def whitelist(self):
        if self._target is None:
            raise ValueError("Cannot access whitelist before preset is baked (use ._whitelist instead)")
        return self.target.whitelist

    @property
    def blacklist(self):
        if self._target is None:
            raise ValueError("Cannot access blacklist before preset is baked (use ._blacklist instead)")
        return self.target.blacklist

    @property
    def preset_dir(self):
        return self.bbot_home / "presets"

    @property
    def default_output_modules(self):
        if self._default_output_modules is not None:
            output_modules = self._default_output_modules
        else:
            output_modules = ["python", "csv", "txt", "json"]
            if self._cli:
                output_modules.append("stdout")
        return output_modules

    @property
    def default_internal_modules(self):
        preloaded_internal = self.module_loader.preloaded(type="internal")
        if self._default_internal_modules is not None:
            internal_modules = self._default_internal_modules
        else:
            internal_modules = list(preloaded_internal)
        return {k: preloaded_internal[k] for k in internal_modules}

    def merge(self, other):
        """
        Merge another preset into this one.

        If there are any config conflicts, `other` will win over `self`.

        Args:
            other (Preset): The preset to merge into this one.

        Examples:
            >>> preset1 = Preset(modules=["portscan"])
            >>> preset1.scan_modules
            ['portscan']
            >>> preset2 = Preset(modules=["sslcert"])
            >>> preset2.scan_modules
            ['sslcert']
            >>> preset1.merge(preset2)
            >>> preset1.scan_modules
            ['portscan', 'sslcert']
        """
        self.log_debug(f'Merging preset "{other.name}" into "{self.name}"')
        # config
        self.core.merge_custom(other.core.custom_config)
        self.module_loader.core = self.core
        # module dirs
        # modules + flags
        # establish requirements / exclusions first
        self.exclude_modules.update(other.exclude_modules)
        self.require_flags.update(other.require_flags)
        self.exclude_flags.update(other.exclude_flags)
        # then it's okay to start enabling modules
        self.explicit_scan_modules.update(other.explicit_scan_modules)
        self.explicit_output_modules.update(other.explicit_output_modules)
        self.flags.update(other.flags)

        # target / scope
        self._seeds.update(other._seeds)
        # leave whitelist as None until we encounter one
        if other._whitelist is not None:
            if self._whitelist is None:
                self._whitelist = set(other._whitelist)
            else:
                self._whitelist.update(other._whitelist)
        self._blacklist.update(other._blacklist)
        self.strict_scope = self.strict_scope or other.strict_scope

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
        self.force_start = self.force_start | other.force_start
        self._cli = self._cli | other._cli

    def bake(self, scan=None):
        """
        Return a "baked" copy of this preset, ready for use by a BBOT scan.

        Baking a preset finalizes it by populating `preset.modules` based on flags,
        performing final validations, and substituting environment variables in preloaded modules.
        It also evaluates custom `conditions` as specified in the preset.

        This function is automatically called in Scanner.__init__(). There is no need to call it manually.
        """
        self.log_debug("Getting baked")
        # create a copy of self
        baked_preset = copy(self)
        baked_preset.scan = scan
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

        # validate flags, config options
        baked_preset.validate()

        # validate log level options
        baked_preset.apply_log_level(apply_core=scan is not None)

        # assign baked preset to our scan
        if scan is not None:
            scan.preset = baked_preset

        # now that our requirements / exclusions are validated, we can start enabling modules
        # enable scan modules
        for module in baked_preset.explicit_scan_modules:
            baked_preset.add_module(module, module_type="scan")

        # enable output modules
        output_modules_to_enable = set(baked_preset.explicit_output_modules)
        default_output_modules = self.default_output_modules
        output_module_override = any(m in default_output_modules for m in output_modules_to_enable)
        # if none of the default output modules have been explicitly specified, enable them all
        if not output_module_override:
            output_modules_to_enable.update(self.default_output_modules)
        for module in output_modules_to_enable:
            baked_preset.add_module(module, module_type="output", raise_error=False)

        # enable internal modules
        for internal_module, preloaded in self.default_internal_modules.items():
            is_enabled = baked_preset.config.get(internal_module, True)
            is_excluded = internal_module in baked_preset.exclude_modules
            if is_enabled and not is_excluded:
                baked_preset.add_module(internal_module, module_type="internal", raise_error=False)

        # disable internal modules if requested
        for internal_module in baked_preset.internal_modules:
            if baked_preset.config.get(internal_module, True) == False:
                baked_preset.exclude_modules.add(internal_module)

        # enable modules by flag
        for flag in baked_preset.flags:
            for module, preloaded in baked_preset.module_loader.preloaded().items():
                module_flags = preloaded.get("flags", [])
                module_type = preloaded.get("type", "scan")
                if flag in module_flags:
                    self.log_debug(f'Enabling module "{module}" because it has flag "{flag}"')
                    baked_preset.add_module(module, module_type, raise_error=False)

        # ensure we have output modules
        if not baked_preset.output_modules:
            for output_module in self.default_output_modules:
                baked_preset.add_module(output_module, module_type="output", raise_error=False)

        # create target object
        from bbot.scanner.target import BBOTTarget

        baked_preset._target = BBOTTarget(
            *list(self._seeds),
            whitelist=self._whitelist,
            blacklist=self._blacklist,
            strict_scope=self.strict_scope,
            scan=scan,
        )

        # evaluate conditions
        if baked_preset.conditions:
            from .conditions import ConditionEvaluator

            evaluator = ConditionEvaluator(baked_preset)
            evaluator.evaluate()

        self._baked = True
        return baked_preset

    def parse_args(self):
        """
        Parse CLI arguments, and merge them into this preset.

        Used in `cli.py`.
        """
        self._cli = True
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
    def scan_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "scan"]

    @property
    def output_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "output"]

    @property
    def internal_modules(self):
        return [m for m in self.modules if self.preloaded_module(m).get("type", "scan") == "internal"]

    def add_module(self, module_name, module_type="scan", raise_error=True):
        self.log_debug(f'Adding module "{module_name}" of type "{module_type}"')
        is_valid, reason, preloaded = self._is_valid_module(module_name, module_type, raise_error=raise_error)
        if not is_valid:
            self.log_debug(f'Unable to add {module_type} module "{module_name}": {reason}')
            return
        self.modules.add(module_name)
        for module_dep in preloaded.get("deps", {}).get("modules", []):
            if module_dep != module_name and module_dep not in self.modules:
                self.log_verbose(f'Adding module "{module_dep}" because {module_name} depends on it')
                self.add_module(module_dep, raise_error=False)

    def preloaded_module(self, module):
        return self.module_loader.preloaded()[module]

    @property
    def config(self):
        return self.core.config

    @property
    def web_config(self):
        return self.core.config.get("web", {})

    def apply_log_level(self, apply_core=False):
        # silent takes precedence
        if self.silent:
            self.verbose = False
            self.debug = False
            if apply_core:
                self.core.logger.log_level = "CRITICAL"
                for key in ("verbose", "debug"):
                    with suppress(omegaconf.errors.ConfigKeyError):
                        del self.core.custom_config[key]
        else:
            # then debug
            if self.debug:
                self.verbose = False
                if apply_core:
                    self.core.logger.log_level = "DEBUG"
                    with suppress(omegaconf.errors.ConfigKeyError):
                        del self.core.custom_config["verbose"]
            else:
                # finally verbose
                if self.verbose and apply_core:
                    self.core.logger.log_level = "VERBOSE"

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
            from bbot.core.modules import MODULE_LOADER

            self._module_loader = MODULE_LOADER
            self._module_loader.ensure_config_files()

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

    def in_scope(self, host):
        return self.target.in_scope(host)

    def blacklisted(self, host):
        return self.target.blacklisted(host)

    def whitelisted(self, host):
        return self.target.whitelisted(host)

    @classmethod
    def from_dict(cls, preset_dict, name=None, _exclude=None, _log=False):
        """
        Create a preset from a Python dictionary object.

        Args:
            preset_dict (dict): Preset in dictionary form
            name (str, optional): Name of preset
            _exclude (list[Path], optional): Preset filenames to exclude from inclusion. Used internally to prevent infinite recursion in circular or self-referencing presets.
            _log (bool, optional): Whether to enable logging for the preset. This will record which modules/flags are enabled, etc.

        Returns:
            Preset: The loaded preset

        Examples:
            >>> preset = Preset.from_dict({"target": ["evilcorp.com"], "modules": ["portscan"]})
        """
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
        """
        Load a preset from a yaml file and merge it into this one.

        If the full path is not specified, BBOT will look in all the usual places for it.

        The file extension is optional.

        Args:
            filename (Path): The preset YAML file to merge

        Examples:
            >>> preset.include_preset("/home/user/my_preset.yml")
        """
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

        Examples:
            >>> preset = Preset.from_yaml_file("/home/user/my_preset.yml")
        """
        filename = Path(filename).resolve()
        try:
            return _preset_cache[filename]
        except KeyError:
            if _exclude is None:
                _exclude = set()
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
            preset = cls.from_dict(
                omegaconf.OmegaConf.create(yaml_str), name=filename.stem, _exclude=_exclude, _log=_log
            )
            preset._yaml_str = yaml_str
            _preset_cache[filename] = preset
            return preset

    @classmethod
    def from_yaml_string(cls, yaml_preset):
        """
        Create a preset from a YAML file. If the full path is not specified, BBOT will look in all the usual places for it.

        The file extension is optional.

        Examples:
            >>> yaml_string = '''
            >>> target:
            >>> - evilcorp.com
            >>> modules:
            >>> - portscan'''
            >>> preset = Preset.from_yaml_string(yaml_string)
        """
        return cls.from_dict(omegaconf.OmegaConf.create(yaml_preset))

    def to_dict(self, include_target=False, full_config=False, redact_secrets=False):
        """
        Convert this preset into a Python dictionary.

        Args:
            include_target (bool, optional): If True, include target, whitelist, and blacklist in the dictionary
            full_config (bool, optional): If True, include the entire config, not just what's changed from the defaults.

        Returns:
            dict: The preset in dictionary form

        Examples:
            >>> preset = Preset(flags=["subdomain-enum"], modules=["portscan"])
            >>> preset.to_dict()
            {"flags": ["subdomain-enum"], "modules": ["portscan"]}
        """
        preset_dict = {}

        # config
        if full_config:
            config = self.core.config
        else:
            config = self.core.custom_config
        config = omegaconf.OmegaConf.to_object(config)
        if redact_secrets:
            config = self.core.no_secrets_config(config)
        if config:
            preset_dict["config"] = config

        # scope
        if include_target:
            target = sorted(str(t.data) for t in self.target.seeds)
            whitelist = []
            if self.target.whitelist is not None:
                whitelist = sorted(str(t.data) for t in self.target.whitelist)
            blacklist = sorted(str(t.data) for t in self.target.blacklist)
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
        if self.explicit_scan_modules:
            preset_dict["modules"] = sorted(self.explicit_scan_modules)
        if self.explicit_output_modules:
            preset_dict["output_modules"] = sorted(self.explicit_output_modules)

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
        """
        Return the preset in the form of a YAML string.

        Args:
            include_target (bool, optional): If True, include target, whitelist, and blacklist in the dictionary
            full_config (bool, optional): If True, include the entire config, not just what's changed from the defaults.
            sort_keys (bool, optional): If True, sort YAML keys alphabetically

        Returns:
            str: The preset in the form of a YAML string

        Examples:
            >>> preset = Preset(flags=["subdomain-enum"], modules=["portscan"])
            >>> print(preset.to_yaml())
            flags:
            - subdomain-enum
            modules:
            - portscan
        """
        preset_dict = self.to_dict(include_target=include_target, full_config=full_config)
        return yaml.dump(preset_dict, sort_keys=sort_keys)

    def _is_valid_module(self, module, module_type, name_only=False, raise_error=True):
        if module_type == "scan":
            module_choices = self.module_loader.scan_module_choices
        elif module_type == "output":
            module_choices = self.module_loader.output_module_choices
        elif module_type == "internal":
            module_choices = self.module_loader.internal_module_choices
        else:
            raise ValidationError(f'Unknown module type "{module}"')

        if not module in module_choices:
            raise ValidationError(get_closest_match(module, module_choices, msg=f"{module_type} module"))

        try:
            preloaded = self.module_loader.preloaded()[module]
        except KeyError:
            raise ValidationError(f'Unknown module "{module}"')

        if name_only:
            return True, "", preloaded

        if module in self.exclude_modules:
            reason = "the module has been excluded"
            if raise_error:
                raise ValidationError(f'Unable to add {module_type} module "{module}" because {reason}')
            return False, reason, {}

        module_flags = preloaded.get("flags", [])
        _module_type = preloaded.get("type", "scan")
        if module_type:
            if _module_type != module_type:
                reason = f'its type ({_module_type}) is not "{module_type}"'
                if raise_error:
                    raise ValidationError(f'Unable to add {module_type} module "{module}" because {reason}')
                return False, reason, preloaded

        if _module_type == "scan":
            if self.exclude_flags:
                for f in module_flags:
                    if f in self.exclude_flags:
                        return False, f'it has excluded flag, "{f}"', preloaded
            if self.require_flags and not all(f in module_flags for f in self.require_flags):
                return False, f'it doesn\'t have the required flags ({",".join(self.require_flags)})', preloaded

        return True, "", preloaded

    def validate(self):
        """
        Validate module/flag exclusions/requirements, and CLI config options if applicable.
        """
        if self._cli:
            self.args.validate()

        # validate excluded modules
        for excluded_module in self.exclude_modules:
            if not excluded_module in self.module_loader.all_module_choices:
                raise ValidationError(
                    get_closest_match(excluded_module, self.module_loader.all_module_choices, msg="module")
                )
        # validate excluded flags
        for excluded_flag in self.exclude_flags:
            if not excluded_flag in self.module_loader.flag_choices:
                raise ValidationError(get_closest_match(excluded_flag, self.module_loader.flag_choices, msg="flag"))
        # validate required flags
        for required_flag in self.require_flags:
            if not required_flag in self.module_loader.flag_choices:
                raise ValidationError(get_closest_match(required_flag, self.module_loader.flag_choices, msg="flag"))
        # validate flags
        for flag in self.flags:
            if not flag in self.module_loader.flag_choices:
                raise ValidationError(get_closest_match(flag, self.module_loader.flag_choices, msg="flag"))

    @property
    def all_presets(self):
        """
        Recursively find all the presets and return them as a dictionary
        """
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
                            if loaded_preset is False:
                                continue
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

                        # collapse home directory into "~"
                        if local_preset.is_relative_to(home_dir):
                            local_preset = Path("~") / local_preset.relative_to(home_dir)

                        presets[local_preset] = (loaded_preset, category, preset_path, original_filename)

            # sort by name
            DEFAULT_PRESETS = dict(sorted(presets.items(), key=lambda x: x[-1][0].name))
        return DEFAULT_PRESETS

    def presets_table(self, include_modules=True):
        """
        Return a table of all the presets in the form of a string
        """
        table = []
        header = ["Preset", "Category", "Description", "# Modules"]
        if include_modules:
            header.append("Modules")
        for yaml_file, (loaded_preset, category, preset_path, original_file) in self.all_presets.items():
            loaded_preset = loaded_preset.bake()
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
