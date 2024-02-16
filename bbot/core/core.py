from pathlib import Path
from omegaconf import OmegaConf


bbot_code_dir = Path(__file__).parent.parent


class BBOTCore:

    default_module_dir = bbot_code_dir / "modules"

    def __init__(self):
        self._args = None
        self._logger = None
        self._environ = None
        self._files_config = None
        self._module_loader = None

        self.bbot_sudo_pass = None
        self.cli_execution = False

        self._config = None
        self._default_config = None
        self._custom_config = None

        # where to load modules from
        self.module_dirs = self.config.get("module_dirs", [])
        self.module_dirs = [Path(p) for p in self.module_dirs] + [self.default_module_dir]
        self.module_dirs = sorted(set(self.module_dirs))

        # ensure bbot home dir
        if not "home" in self.config:
            self.custom_config["home"] = "~/.bbot"
        self.home = Path(self.config["home"]).expanduser().resolve()
        self.cache_dir = self.home / "cache"
        self.tools_dir = self.home / "tools"
        self.scans_dir = self.home / "scans"

        # bare minimum == logging
        self.logger

        # PRESET TODO: add back in bbot/core/configurator/__init__.py
        # - check_cli_args
        # - ensure_config_files

        # first, we load config files
        #    - ensure bbot home directory (needed for logging)
        #    - ensure module load directories (needed for preloading modules)

        ### to save on performance, we stop here
        ### the rest of the attributes populate lazily only when accessed
        ### we do this to minimize the time it takes to import bbot as a code library

        # next, we preload modules (needed for parsing CLI args)
        # self.load_module_configs()

        # next, we load environment variables
        # todo: automatically propagate config values to environ? (would require __setitem__ hooks)
        # self.load_environ()

        # finally, we parse CLI args
        # self.parse_cli_args()

    @property
    def files_config(self):
        if self._files_config is None:
            from .config import files

            self.files = files
            self._files_config = files.BBOTConfigFiles(self)
        return self._files_config

    @property
    def config(self):
        """
        .config is just .default_config + .custom_config merged together

        any new values should be added to custom_config.
        """
        if self._config is None:
            self._config = OmegaConf.merge(self.default_config, self.custom_config)
            # set read-only flag (change .custom_config instead)
            OmegaConf.set_readonly(self._config, True)
        return self._config

    @property
    def default_config(self):
        if self._default_config is None:
            self._default_config = self.files_config.get_default_config()
            # set read-only flag (change .custom_config instead)
            OmegaConf.set_readonly(self._default_config, True)
        return self._default_config

    @default_config.setter
    def default_config(self, value):
        # we temporarily clear out the config so it can be refreshed if/when default_config changes
        self._config = None
        self._default_config = value

    @property
    def custom_config(self):
        # we temporarily clear out the config so it can be refreshed if/when custom_config changes
        self._config = None
        if self._custom_config is None:
            self._custom_config = self.files_config.get_custom_config()
        return self._custom_config

    @custom_config.setter
    def custom_config(self, value):
        # we temporarily clear out the config so it can be refreshed if/when custom_config changes
        self._config = None
        self._custom_config = value

    @property
    def logger(self):
        self.config
        if self._logger is None:
            from .config.logger import BBOTLogger

            self._logger = BBOTLogger(self)
        return self._logger

    @property
    def module_loader(self):
        # module loader depends on environment to be set up
        # or is it the other way around
        # PRESET TODO
        self.environ
        if self._module_loader is None:
            from .modules import ModuleLoader

            self._module_loader = ModuleLoader(self)

            # update default config with module defaults
            module_config = OmegaConf.create(
                {
                    "modules": self._module_loader.configs(type="scan"),
                    "output_modules": self._module_loader.configs(type="output"),
                    "internal_modules": self._module_loader.configs(type="internal"),
                }
            )
            self.default_config = OmegaConf.merge(self.default_config, module_config)

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
            from .config.args import BBOTArgs

            self._args = BBOTArgs(self)
        return self._args
