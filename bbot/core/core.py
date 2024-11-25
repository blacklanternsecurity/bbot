import os
import logging
from copy import copy
from pathlib import Path
from contextlib import suppress
from omegaconf import OmegaConf

from bbot.errors import BBOTError
from .multiprocess import SHARED_INTERPRETER_STATE


DEFAULT_CONFIG = None


class BBOTCore:
    """
    This is the first thing that loads when you import BBOT.

    Unlike a Preset, BBOTCore holds only the config, not scan-specific stuff like targets, flags, modules, etc.

    Its main jobs are:

    - set up logging
    - keep separation between the `default` and `custom` config (this allows presets to only display the config options that have changed)
    - allow for easy merging of configs
    - load quickly
    """

    # used for filtering out sensitive config values
    secrets_strings = ["api_key", "username", "password", "token", "secret", "_id"]
    # don't filter/remove entries under this key
    secrets_exclude_keys = ["modules"]

    def __init__(self):
        self._logger = None
        self._files_config = None

        self._config = None
        self._custom_config = None

        # bare minimum == logging
        self.logger
        self.log = logging.getLogger("bbot.core")

        self._prep_multiprocessing()

    def _prep_multiprocessing(self):
        import multiprocessing
        from .helpers.process import BBOTProcess

        if SHARED_INTERPRETER_STATE.is_main_process:
            # if this is the main bbot process, set the logger and queue for the first time
            from functools import partialmethod

            BBOTProcess.__init__ = partialmethod(
                BBOTProcess.__init__, log_level=self.logger.log_level, log_queue=self.logger.queue
            )

        # this makes our process class the default for process pools, etc.
        mp_context = multiprocessing.get_context("spawn")
        mp_context.Process = BBOTProcess

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
        """
        The default BBOT config (from `defaults.yml`). Read-only.
        """
        global DEFAULT_CONFIG
        if DEFAULT_CONFIG is None:
            self.default_config = self.files_config.get_default_config()
            # ensure bbot home dir
            if "home" not in self.default_config:
                self.default_config["home"] = "~/.bbot"
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
        """
        Custom BBOT config (from `~/.config/bbot/bbot.yml`)
        """
        # we temporarily clear out the config so it can be refreshed if/when custom_config changes
        self._config = None
        if self._custom_config is None:
            self.custom_config = self.files_config.get_custom_config()
        return self._custom_config

    @custom_config.setter
    def custom_config(self, value):
        # we temporarily clear out the config so it can be refreshed if/when custom_config changes
        self._config = None
        # ensure the modules key is always a dictionary
        modules_entry = value.get("modules", None)
        if modules_entry is not None and not OmegaConf.is_dict(modules_entry):
            value["modules"] = {}
        self._custom_config = value

    def no_secrets_config(self, config):
        from .helpers.misc import clean_dict

        with suppress(ValueError):
            config = OmegaConf.to_object(config)

        return clean_dict(
            config,
            *self.secrets_strings,
            fuzzy=True,
            exclude_keys=self.secrets_exclude_keys,
        )

    def secrets_only_config(self, config):
        from .helpers.misc import filter_dict

        with suppress(ValueError):
            config = OmegaConf.to_object(config)

        return filter_dict(
            config,
            *self.secrets_strings,
            fuzzy=True,
            exclude_keys=self.secrets_exclude_keys,
        )

    def merge_custom(self, config):
        """
        Merge a config into the custom config.
        """
        self.custom_config = OmegaConf.merge(self.custom_config, OmegaConf.create(config))

    def merge_default(self, config):
        """
        Merge a config into the default config.
        """
        self.default_config = OmegaConf.merge(self.default_config, OmegaConf.create(config))

    def copy(self):
        """
        Return a semi-shallow copy of self. (`custom_config` is copied, but `default_config` stays the same)
        """
        core_copy = copy(self)
        core_copy._custom_config = self._custom_config.copy()
        return core_copy

    @property
    def files_config(self):
        """
        Get the configs from `bbot.yml` and `defaults.yml`
        """
        if self._files_config is None:
            from .config import files

            self.files = files
            self._files_config = files.BBOTConfigFiles(self)
        return self._files_config

    def create_process(self, *args, **kwargs):
        if os.environ.get("BBOT_TESTING", "") == "True":
            process = self.create_thread(*args, **kwargs)
        else:
            if SHARED_INTERPRETER_STATE.is_scan_process:
                from .helpers.process import BBOTProcess

                process = BBOTProcess(*args, **kwargs)
            else:
                import multiprocessing

                raise BBOTError(f"Tried to start server from process {multiprocessing.current_process().name}")
        process.daemon = True
        return process

    def create_thread(self, *args, **kwargs):
        from .helpers.process import BBOTThread

        return BBOTThread(*args, **kwargs)

    @property
    def logger(self):
        self.config
        if self._logger is None:
            from .config.logger import BBOTLogger

            self._logger = BBOTLogger(self)
        return self._logger
