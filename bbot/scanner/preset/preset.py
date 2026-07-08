import os
import yaml
import logging
import traceback
from copy import copy
from pathlib import Path

from .path import PRESET_PATH

from bbot.errors import *
from bbot.core import CORE
from bbot.core.helpers.misc import make_table, mkdir, get_closest_match


log = logging.getLogger("bbot.presets")


_preset_cache = {}


# cache default presets to prevent having to reload from disk
DEFAULT_PRESETS = None


class BasePreset(type):
    def __call__(cls, *args, include=None, presets=None, name=None, description=None, _exclude=None, **kwargs):
        """
        Handles loading of "included" presets, while preserving the proper load order

        Overriding __call__() allows us to reuse the logic from .merge() without duplicating functionality in __init__().
        """
        include_preset = None

        # "presets" is alias to "include"
        if presets and include:
            raise ValueError(
                'Cannot use both "presets" and "include" args at the same time (presets is an alias to include). Please pick one or the other :)'
            )
        if presets and not include:
            include = presets
        # include other presets
        if include and not isinstance(include, (list, tuple, set)):
            include = [include]

        main_preset = type.__call__(cls, *args, name=name, description=description, _exclude=_exclude, **kwargs)

        if include:
            include_preset = type.__call__(cls, name=name, description=description, _exclude=_exclude)
            for included_preset in include:
                include_preset.include_preset(included_preset)
            include_preset.merge(main_preset)
            return include_preset

        return main_preset


class Preset(metaclass=BasePreset):
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
        target (BBOTTarget): The scan target object containing seeds, target, and blacklist.
            Use `target.target` to access what's in the target (what `in_target()` checks).
        blacklist (Target): Scan blacklist (this takes ultimate precedence).
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
        config (dict): BBOT config (alias to `core.config`)
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
        *target,
        seeds=None,
        blacklist=None,
        modules=None,
        output_modules=None,
        exclude_modules=None,
        exclude_output_modules=None,
        flags=None,
        require_flags=None,
        exclude_flags=None,
        config=None,
        module_dirs=None,
        output_dir=None,
        name=None,
        description=None,
        scan_name=None,
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
            *target (str): Target(s) to scan. These ALWAYS become the target (what `in_target()` checks).
                Types supported: hostnames, IPs, CIDRs, emails, open ports.
                Note: Positional arguments always mean target, never seeds.
            seeds (list, optional): Explicitly define seeds (initial events for passive modules).
                If not specified, seeds will be backfilled from target when target is defined.
            blacklist (list, optional): Blacklisted target(s). Takes ultimate precedence. Defaults to empty.
            modules (list[str], optional): List of scan modules to enable for the scan. Defaults to empty list.
            output_modules (list[str], optional): Additional output modules to enable (additive on top of defaults).
            exclude_modules (list[str], optional): List of modules to exclude from the scan.
            exclude_output_modules (list[str], optional): Output modules to exclude (e.g. to remove defaults).
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
        # whether this preset has been validated+coerced (a precondition for bake())
        self._validated = False

        self._default_output_modules = None
        self._default_internal_modules = None

        # modules / flags
        self.modules = set()
        self.exclude_modules = set()
        self.exclude_output_modules = set()
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
        if exclude_output_modules is None:
            exclude_output_modules = []
        if isinstance(exclude_output_modules, str):
            exclude_output_modules = [exclude_output_modules]
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

        # custom conditions, evaluated during Scanner._prep()
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
            config = {}
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

        # target / seeds / blacklist
        # these are temporary receptacles until they all get .baked() together
        self._target_list = set(target or [])
        self._blacklist = set(blacklist if blacklist else [])
        # seeds are special. Instead of initializing them as an empty set, we use "None"
        # to signify they haven't been explicitly set.
        # after all the merging is done, if seeds are still untouched by the user
        # (i.e. they are still None), we'll know it's okay to copy them from the targets.
        self._seeds = set(seeds) if seeds else None

        # _target doesn't get set until .bake()
        self._target = None

        # we don't fill self.modules yet (that happens in .bake())
        self.explicit_scan_modules.update(set(modules))
        self.explicit_output_modules.update(set(output_modules))
        self.exclude_modules.update(set(exclude_modules))
        self.exclude_output_modules.update(set(exclude_output_modules))
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
    def seeds(self):
        if self._target is None:
            raise ValueError("Cannot access target before preset is baked (use ._seeds instead)")
        return self.target.seeds

    @property
    def blacklist(self):
        if self._target is None:
            raise ValueError("Cannot access blacklist before preset is baked (use ._blacklist instead)")
        return self.target.blacklist

    @property
    def preset_dir(self):
        return (self.bbot_home / "presets").expanduser().resolve()

    @property
    def default_output_modules(self):
        if self._default_output_modules is not None:
            output_modules = self._default_output_modules
        else:
            output_modules = ["csv", "txt", "json"]
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
        self.exclude_output_modules.update(other.exclude_output_modules)
        self.require_flags.update(other.require_flags)
        self.exclude_flags.update(other.exclude_flags)
        # then it's okay to start enabling modules
        self.explicit_scan_modules.update(other.explicit_scan_modules)
        self.explicit_output_modules.update(other.explicit_output_modules)
        self.flags.update(other.flags)

        # target / scope
        self._target_list.update(other._target_list)
        if other._seeds is not None:
            if self._seeds is None:
                self._seeds = set(other._seeds)
            else:
                self._seeds.update(other._seeds)
        self._blacklist.update(other._blacklist)

        # module dirs
        self.module_dirs = self.module_dirs.union(other.module_dirs)

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
        # transfer args
        if other._args is not None:
            self._args = other._args
        # the preset changed -- it must be re-validated before baking
        self._validated = False

    def bake(self, scan=None):
        """
        Return a "baked" copy of this preset, ready for use by a BBOT scan.

        Presets can be merged and modified before baking, but once baked, they are immutable.

        Baking a preset finalizes it by populating `preset.modules` based on flags,
        performing final validations, and substituting environment variables in preloaded modules.

        This function is automatically called in Scanner.__init__(). There is no need to call it manually.
        """
        self.log_debug("Getting baked")
        # create a copy of self
        baked_preset = copy(self)

        # copy core
        baked_preset.core = self.core.copy()

        if scan is not None:
            baked_preset.scan = scan
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

        # bake() requires an already validated + coerced preset. Validation and
        # coercion are a PRECONDITION (Preset.validate(), the caller's
        # responsibility) -- enforced here so an unvalidated preset never bakes.
        if not self._validated:
            raise ValidationError(
                "Preset must be validated before baking -- call .validate() first "
                "(Scanner and the CLI do this for you)."
            )

        # validate log level options
        baked_preset.apply_log_level(apply_core=scan is not None)

        # now that our requirements / exclusions are validated, we can start enabling modules
        # enable scan modules
        for module in baked_preset.explicit_scan_modules:
            baked_preset.add_module(module, module_type="scan")

        # enable output modules (always additive: defaults + explicit, minus excluded)
        output_modules_to_enable = set(self.default_output_modules)
        output_modules_to_enable.update(baked_preset.explicit_output_modules)
        output_modules_to_enable -= baked_preset.exclude_output_modules
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
            if baked_preset.config.get(internal_module, True) is False:
                baked_preset.exclude_modules.add(internal_module)

        # enable modules by flag
        for flag in baked_preset.flags:
            for module, preloaded in baked_preset.module_loader.preloaded().items():
                module_flags = preloaded.get("flags", [])
                module_type = preloaded.get("type", "scan")
                if flag in module_flags:
                    self.log_debug(f'Enabling module "{module}" because it has flag "{flag}"')
                    baked_preset.add_module(module, module_type, raise_error=False)

        # ensure we have output modules (unless the user explicitly excluded them)
        if not baked_preset.output_modules and not baked_preset.exclude_output_modules:
            for output_module in self.default_output_modules:
                baked_preset.add_module(output_module, module_type="output", raise_error=False)

        # dnsresolve is the intercept module that resolves every event, tags wildcards/unresolved,
        # and rewrites wildcard hits to `_wildcard.parent`. Modules that watch DNS_NAME depend on
        # those tags to filter false positives; without it, brute-force and passive-enum modules
        # emit unverified and wildcard-tainted names. This catches all three explicit opt-outs:
        # `-em dnsresolve`, top-level `dnsresolve: false`, and `dns.disable: true`. We check the
        # user actions rather than "dnsresolve in modules" so that internal-module-trimming code
        # paths (e.g. `--list-module-options` setting `_default_internal_modules = []`) don't trip
        # the gate -- those aren't real scans, and the user hasn't asked to disable anything.
        dnsresolve_disabled = (
            "dnsresolve" in baked_preset.exclude_modules
            or baked_preset.config.get("dnsresolve", True) is False
            or baked_preset.config.get("dns", {}).get("disable", False)
        )
        if dnsresolve_disabled:
            dns_name_consumers = sorted(
                m
                for m in baked_preset.modules
                if "DNS_NAME" in baked_preset.preloaded_module(m).get("watched_events", [])
            )
            if dns_name_consumers:
                raise ValidationError(
                    f"dnsresolve is required by these enabled modules but is disabled: {', '.join(dns_name_consumers)}. "
                    "Use `dns.minimal: true` (resolves A/AAAA only, skips MX/NS/SRV expansion) "
                    "if you want to reduce DNS overhead while keeping wildcard and unresolved tagging. "
                    "If you genuinely want no DNS at all, also disable the modules listed above."
                )

        # create target object
        from bbot.scanner.target import BBOTTarget

        baked_preset._target = BBOTTarget(
            seeds=list(self._seeds) if self._seeds else None,
            target=list(self._target_list),
            blacklist=self._blacklist,
            strict_scope=self.strict_scope,
        )

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

    @property
    def scope_config(self):
        return self.config.get("scope", {})

    @property
    def strict_scope(self):
        return self.scope_config.get("strict", False)

    def apply_log_level(self, apply_core=False):
        """
        Apply the log level to the preset.

        Args:
            apply_core (bool, optional): If True, apply the log level to the core logger.
        """
        # silent takes precedence
        if self.silent:
            self.verbose = False
            self.debug = False
            if apply_core:
                self.core.logger.log_level = "CRITICAL"
                for key in ("verbose", "debug"):
                    self.core.custom_config.pop(key, None)
        else:
            # then debug
            if self.debug:
                self.verbose = False
                if apply_core:
                    self.core.logger.log_level = "DEBUG"
                    self.core.custom_config.pop("verbose", None)
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

    def in_target(self, host):
        return self.target.in_target(host)

    @staticmethod
    def _resolve_file_entries(entries):
        """Resolve relative file paths in target/seeds/blacklist entries via PresetPath.

        Replaces entries that match a file in PresetPath's known directories with
        their absolute path, so that chain_lists' existing try_files logic can find them.
        Entries that don't match a file are left as-is.
        """
        resolved = []
        for entry in entries:
            found = PRESET_PATH.find_file(entry)
            if found is not None:
                resolved.append(str(found))
            else:
                resolved.append(entry)
        return resolved

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
        from .validate import prevalidate_preset

        # Gate top-level keys only -- .get() below would silently drop a typo like
        # `modlues:`. Config values + _validated are validate()'s job, not from_dict's.
        errs = prevalidate_preset(preset_dict)
        if errs:
            raise ValidationError("\n".join(str(e) for e in errs))

        from bbot.core.helpers.misc import chain_lists

        # Handle seeds and targets from dict
        # for user-friendliness, we allow both "target" and "targets" to be used. we merge them into a single list.
        target_vals = (preset_dict.get("target") or []) + (preset_dict.get("targets") or [])
        # resolve relative file paths via PresetPath (which knows the preset's directory)
        targets = chain_lists(
            cls._resolve_file_entries(target_vals),
            try_files=True,
            msg="Reading targets from preset file: {filename}",
            _strip_comments=True,
        )
        seeds = preset_dict.get("seeds")
        if seeds is not None:
            seeds = chain_lists(
                cls._resolve_file_entries(seeds),
                try_files=True,
                msg="Reading seeds from preset file: {filename}",
                _strip_comments=True,
            )
        blacklist = preset_dict.get("blacklist")
        if blacklist is not None:
            blacklist = chain_lists(
                cls._resolve_file_entries(blacklist),
                try_files=True,
                msg="Reading blacklist from preset file: {filename}",
                _strip_comments=True,
            )
        new_preset = cls(
            *targets,
            seeds=seeds,
            blacklist=blacklist,
            modules=preset_dict.get("modules"),
            output_modules=preset_dict.get("output_modules"),
            exclude_modules=preset_dict.get("exclude_modules"),
            exclude_output_modules=preset_dict.get("exclude_output_modules"),
            flags=preset_dict.get("flags"),
            require_flags=preset_dict.get("require_flags"),
            exclude_flags=preset_dict.get("exclude_flags"),
            verbose=preset_dict.get("verbose", False),
            debug=preset_dict.get("debug", False),
            silent=preset_dict.get("silent", False),
            config=preset_dict.get("config"),
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
        preset_from_yaml = self.from_yaml_file(filename, _exclude=self._preset_files_loaded)
        if preset_from_yaml is not False:
            self.merge(preset_from_yaml)
            self._preset_files_loaded.add(preset_from_yaml.filename)

    @classmethod
    def from_yaml_file(cls, filename, _exclude=None, _log=False):
        """
        Create a preset from a YAML file. If the full path is not specified, BBOT will look in all the usual places for it.

        The file extension is optional.

        Examples:
            >>> preset = Preset.from_yaml_file("/home/user/my_preset.yml")
        """
        filename = PRESET_PATH.find(filename)
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
            try:
                yaml_dict = yaml.safe_load(yaml_str) or {}
            except yaml.YAMLError as e:
                raise ValidationError(
                    f"YAML syntax error in {filename}:\n\n{e}\n\nPlease check the file for indentation or formatting errors."
                )
            preset = cls.from_dict(
                yaml_dict,
                name=filename.stem,
                _exclude=_exclude,
                _log=_log,
            )
            preset._yaml_str = yaml_str
            preset.filename = filename
            _preset_cache[filename] = preset
            return preset

    @classmethod
    def from_yaml_string(cls, yaml_preset):
        """
        Create a preset from a YAML string.

        The file extension is optional.

        Examples:
            >>> yaml_string = '''
            >>> target:
            >>> - evilcorp.com
            >>> modules:
            >>> - portscan'''
            >>> preset = Preset.from_yaml_string(yaml_string)
        """
        try:
            yaml_dict = yaml.safe_load(yaml_preset) or {}
        except yaml.YAMLError as e:
            raise ValidationError(
                f"YAML syntax error in preset:\n\n{e}\n\nPlease check the YAML for indentation or formatting errors."
            )
        return cls.from_dict(yaml_dict)

    def to_dict(self, include_target=False, full_config=False, redact_secrets=False):
        """
        Convert this preset into a Python dictionary.

        Args:
            include_target (bool, optional): If True, include seeds, target, and blacklist in the dictionary
            full_config (bool, optional): If True, include the entire config, not just what's changed from the defaults.

        Returns:
            dict: The preset in dictionary form

        Examples:
            >>> preset = Preset(flags=["subdomain-enum"], modules=["portscan"])
            >>> preset.to_dict()
            {"flags": ["subdomain-enum"], "modules": ["portscan"]}
        """
        preset_dict = {}

        if self.description:
            preset_dict["description"] = self.description

        # config
        if full_config:
            config = dict(self.core.config)
        else:
            config = dict(self.core.custom_config)
        if redact_secrets:
            config = self.core.no_secrets_config(config)
        if config:
            preset_dict["config"] = config

        # scope
        if include_target:
            target = sorted(self.target.target.inputs)
            seeds = []
            if self.target.seeds is not None:
                seeds = sorted(self.target.seeds.inputs)
            blacklist = sorted(self.target.blacklist.inputs)
            if target:
                preset_dict["target"] = target
            if seeds and seeds != target:
                preset_dict["seeds"] = seeds
            if blacklist:
                preset_dict["blacklist"] = blacklist

        # flags + modules
        if self.require_flags:
            preset_dict["require_flags"] = sorted(self.require_flags)
        if self.exclude_flags:
            preset_dict["exclude_flags"] = sorted(self.exclude_flags)
        if self.exclude_modules:
            preset_dict["exclude_modules"] = sorted(self.exclude_modules)
        if self.exclude_output_modules:
            preset_dict["exclude_output_modules"] = sorted(self.exclude_output_modules)
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
        if self.scan_name and self.output_dir is not None:
            preset_dict["output_dir"] = str(self.output_dir)

        # conditions
        if self.conditions:
            preset_dict["conditions"] = [c[-1] for c in self.conditions]

        return preset_dict

    def to_yaml(self, include_target=False, full_config=False, sort_keys=False, redact_secrets=False):
        """
        Return the preset in the form of a YAML string.

        Args:
            include_target (bool, optional): If True, include seeds, target, and blacklist in the dictionary
            full_config (bool, optional): If True, include the entire config, not just what's changed from the defaults.
            sort_keys (bool, optional): If True, sort YAML keys alphabetically
            redact_secrets (bool, optional): If True, redact secret values from the output

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
        preset_dict = self.to_dict(
            include_target=include_target, full_config=full_config, redact_secrets=redact_secrets
        )
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

        if module not in module_choices:
            raise ValidationError(get_closest_match(module, module_choices, msg=f"{module_type} module"))

        try:
            preloaded = self.module_loader.preloaded()[module]
        except KeyError:
            raise ValidationError(f'Unknown module "{module}"')

        if name_only:
            return True, "", preloaded

        if module in self.exclude_modules:
            reason = "the module has been excluded"
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
                return False, f"it doesn't have the required flags ({','.join(self.require_flags)})", preloaded

        return True, "", preloaded

    def validate(self):
        """
        Coerce config values to their declared types and validate the preset.

        This is a PRECONDITION for bake() (which enforces it): a preset must be
        validated before it can be baked. Idempotent -- safe to call more than
        once. Sets ``self._validated = True`` on success and returns ``self`` so
        it can be chained (e.g. ``preset.validate().bake()``).
        """
        from bbot.core.config.models import coerce_config

        # Coerce config values toward their declared types
        try:
            index = self.module_loader.config_type_index
            self.core.custom_config = coerce_config(self.core.custom_config, index)
        except Exception as e:
            log.debug(f"Config coercion error: {e}")

        # Validate the (coerced) user config against the schema
        from .validate import validate_preset

        errs = validate_preset({"config": dict(self.core.custom_config)}, module_loader=self.module_loader)
        if errs:
            raise ValidationError("\n".join(str(e) for e in errs))

        if self._cli:
            self.args.validate()

        # validate excluded modules
        for excluded_module in self.exclude_modules:
            if excluded_module not in self.module_loader.all_module_choices:
                raise ValidationError(
                    get_closest_match(excluded_module, self.module_loader.all_module_choices, msg="module")
                )
        for excluded_module in self.exclude_output_modules:
            if excluded_module not in self.module_loader.output_module_choices:
                raise ValidationError(
                    get_closest_match(excluded_module, self.module_loader.output_module_choices, msg="output module")
                )
        # validate declared module names so typos fail early
        for scan_module in self.explicit_scan_modules:
            self._is_valid_module(scan_module, "scan", name_only=True)
        for output_module in self.explicit_output_modules:
            self._is_valid_module(output_module, "output", name_only=True)
        # validate excluded flags
        for excluded_flag in self.exclude_flags:
            if excluded_flag not in self.module_loader.flag_choices:
                raise ValidationError(get_closest_match(excluded_flag, self.module_loader.flag_choices, msg="flag"))
        # validate required flags
        for required_flag in self.require_flags:
            if required_flag not in self.module_loader.flag_choices:
                raise ValidationError(get_closest_match(required_flag, self.module_loader.flag_choices, msg="flag"))
        # validate flags
        for flag in self.flags:
            if flag not in self.module_loader.flag_choices:
                raise ValidationError(get_closest_match(flag, self.module_loader.flag_choices, msg="flag"))

        self._validated = True
        return self

    @property
    def all_presets(self):
        """
        Recursively find all the presets and return them as a dictionary
        """
        # first, add local preset dir to PRESET_PATH (listable so -lp enumerates it)
        PRESET_PATH.add_path(self.preset_dir, listable=True)

        # ensure local preset directory exists
        mkdir(self.preset_dir)

        global DEFAULT_PRESETS
        if DEFAULT_PRESETS is None:
            presets = {}
            for preset_path in PRESET_PATH.listable_paths:
                for ext in ("yml", "yaml"):
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
                        if not original_filename.is_relative_to(self.preset_dir):
                            relative_preset = original_filename.relative_to(preset_path)
                            local_preset = self.preset_dir / relative_preset
                            mkdir(local_preset.parent, check_writable=False)
                            if not local_preset.exists():
                                local_preset.symlink_to(original_filename)

                        presets[local_preset.stem] = (loaded_preset, category, preset_path, original_filename)

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
        for loaded_preset, category, preset_path, original_file in self.all_presets.values():
            # Use explicit_scan_modules which contains the raw modules from YAML
            # This avoids needing to call bake()
            explicit_modules = loaded_preset.explicit_scan_modules
            num_modules = f"{len(explicit_modules):,}"
            row = [loaded_preset.name, category, loaded_preset.description, num_modules]
            if include_modules:
                row.append(", ".join(sorted(explicit_modules)))
            table.append(row)
        return make_table(table, header)

    def log_verbose(self, msg):
        if self._log:
            log.verbose(f"Preset {self.name}: {msg}")

    def log_debug(self, msg):
        if self._log:
            log.debug(f"Preset {self.name}: {msg}")
