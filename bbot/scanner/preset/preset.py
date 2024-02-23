import copy
from omegaconf import OmegaConf

from bbot.core import CORE


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
        name=None,
        modules=None,
        output_modules=None,
        output_dir=None,
        config=None,
        dispatcher=None,
        strict_scope=False,
    ):

        self._args = None
        self._environ = None
        self._module_loader = None

        # where to load modules from
        self.module_dirs = self.config.get("module_dirs", [])
        self.module_dirs = [Path(p) for p in self.module_dirs] + [self.default_module_dir]
        self.module_dirs = sorted(set(self.module_dirs))

        # make a copy of BBOT core
        self.core = copy.deepcopy(CORE)
        if config is None:
            config = OmegaConf.create({})
        # merge any custom configs
        self.core.config.merge_custom(config)

    def process_cli_args(self):
        pass

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
    def environ(self):
        if self._environ is None:
            from .config.environ import BBOTEnviron

            self._environ = BBOTEnviron(self)
        return self._environ

    @property
    def args(self):
        if self._args is None:
            from .args import BBOTArgs

            self._args = BBOTArgs(self)
        return self._args
