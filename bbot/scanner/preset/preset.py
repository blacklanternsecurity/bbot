from pathlib import Path
from omegaconf import OmegaConf

from bbot.core import CORE
from bbot.core.event.base import make_event
from bbot.core.errors import ValidationError
from bbot.core.helpers.misc import sha1, rand_string
from bbot.core.helpers.names_generator import random_name


bbot_code_dir = Path(__file__).parent.parent.parent


class Preset:
    """
    CORE should not handle arguments
        which means it shouldn't need access to the module loader

    """

    default_module_dir = bbot_code_dir / "modules"

    def __init__(
        self,
        *targets,
        whitelist=None,
        blacklist=None,
        scan_id=None,
        scan_name=None,
        modules=None,
        output_modules=None,
        output_dir=None,
        config=None,
        dispatcher=None,
        strict_scope=False,
        _cli_execution=False,
    ):
        self._args = None
        self._environ = None
        self._module_loader = None
        self._cli_execution = _cli_execution

        # bbot core config
        self.core = CORE
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
        self.scan_modules = modules
        self.output_modules = output_modules

        # PRESET TODO: preparation of environment
        # self.core.environ.prepare()
        if self.core.config.get("debug", False):
            self.core.logger.set_log_level("DEBUG")

        # dirs to load modules from
        self.module_dirs = self.core.config.get("module_dirs", [])
        self.module_dirs = [Path(p) for p in self.module_dirs] + [self.default_module_dir]
        self.module_dirs = sorted(set(self.module_dirs))

        # config-aware helper
        from bbot.core.helpers.helper import ConfigAwareHelper

        self.helpers = ConfigAwareHelper(preset=self)

        # scan ID
        if scan_id is not None:
            self.scan_id = str(scan_id)
        else:
            self.scan_id = f"SCAN:{sha1(rand_string(20)).hexdigest()}"

        # scan name
        if scan_name is None:
            tries = 0
            while 1:
                if tries > 5:
                    self.scan_name = f"{self.helpers.rand_string(4)}_{self.helpers.rand_string(4)}"
                    break
                self.scan_name = random_name()
                if output_dir is not None:
                    home_path = Path(output_dir).resolve() / self.scan_name
                else:
                    home_path = self.helpers.bbot_home / "scans" / self.scan_name
                if not home_path.exists():
                    break
                tries += 1
        else:
            self.scan_name = str(scan_name)

        # scan output dir
        if output_dir is not None:
            self.scan_home = Path(output_dir).resolve() / self.scan_name
        else:
            self.scan_home = self.helpers.bbot_home / "scans" / self.scan_name

        self.strict_scope = strict_scope

        # target / whitelist / blacklist
        from bbot.scanner.target import Target

        self.target = Target(self, *targets, strict_scope=strict_scope, make_in_scope=True)
        if not whitelist:
            self.whitelist = self.target.copy()
        else:
            self.whitelist = Target(self, *whitelist, strict_scope=self.strict_scope)
        if not blacklist:
            blacklist = []
        self.blacklist = Target(self, *blacklist)

    def parse_args(self):

        from .args import BBOTArgs

        self._args = BBOTArgs(self)

        # bring in presets
        # self.merge(self.args.presets)

        # bring in config
        self.core.merge_custom(self.args.config)

        # bring in misc cli arguments

        # validate config / modules / flags
        # self.args.validate()

    @property
    def config(self):
        return self.core.config

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
        return sorted(set(self.scan_modules + self.output_modules + self.internal_modules))

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
