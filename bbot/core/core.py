from pathlib import Path


class BBOTCore:

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
        if self._config is None:
            from .config.logger import BBOTLogger

            self._config = self.files_config.get_config()
            self._default_config = self._config.copy()
            self._logger = BBOTLogger(self)
        return self._config

    @property
    def default_config(self):
        self.config
        return self._default_config

    @property
    def logger(self):
        self.config
        return self._logger

    @property
    def module_loader(self):
        if self._module_loader is None:
            from .modules import ModuleLoader

            # PRESET TODO: custom module load paths
            module_dirs = self.config.get("module_dirs", [])
            module_dirs = [Path(p) for p in module_dirs]
            module_dirs = list(set(module_dirs))

            self._module_loader = ModuleLoader(module_dirs=module_dirs)

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
