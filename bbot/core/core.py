import logging
from copy import copy
from pathlib import Path
from omegaconf import OmegaConf

DEFAULT_CONFIG = None


class BBOTCore:

    def __init__(self):
        self._logger = None
        self._files_config = None

        self.bbot_sudo_pass = None

        self._config = None
        self._custom_config = None

        # ensure bbot home dir
        if not "home" in self.config:
            self.custom_config["home"] = "~/.bbot"

        # bare minimum == logging
        self.logger
        self.log = logging.getLogger("bbot.core")

    @property
    def home(self):
        return Path(self.config["home"]).expanduser().resolve()

    @property
    def cache_dir(self):
        return self.home / "cache"

    @property
    def tools_dir(self):
        return self.home / "tools"

    @property
    def temp_dir(self):
        return self.home / "temp"

    @property
    def lib_dir(self):
        return self.home / "lib"

    @property
    def scans_dir(self):
        return self.home / "scans"

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
        global DEFAULT_CONFIG
        if DEFAULT_CONFIG is None:
            self.default_config = self.files_config.get_default_config()
        return DEFAULT_CONFIG

    @default_config.setter
    def default_config(self, value):
        # we temporarily clear out the config so it can be refreshed if/when default_config changes
        global DEFAULT_CONFIG
        self._config = None
        DEFAULT_CONFIG = value
        # set read-only flag (change .custom_config instead)
        OmegaConf.set_readonly(DEFAULT_CONFIG, True)

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

    def merge_custom(self, config):
        self.custom_config = OmegaConf.merge(self.custom_config, OmegaConf.create(config))

    def merge_default(self, config):
        self.default_config = OmegaConf.merge(self.default_config, OmegaConf.create(config))

    def copy(self):
        core_copy = copy(self)
        core_copy._custom_config = self._custom_config.copy()
        return core_copy

    @property
    def files_config(self):
        if self._files_config is None:
            from .config import files

            self.files = files
            self._files_config = files.BBOTConfigFiles(self)
        return self._files_config

    @property
    def logger(self):
        self.config
        if self._logger is None:
            from .config.logger import BBOTLogger

            self._logger = BBOTLogger(self)
        return self._logger