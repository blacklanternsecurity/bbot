import os
import logging
from copy import copy, deepcopy
from pathlib import Path

from bbot.errors import BBOTError
from .config.merge import deep_merge
from .multiprocess import SHARED_INTERPRETER_STATE


DEFAULT_CONFIG: dict | None = None


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

    def __init__(self):
        self._logger = None
        self._files_config = None

        self._config: dict | None = None
        self._custom_config: dict | None = None

        # bare minimum == logging
        try:
            self.logger
        except BBOTError as e:
            import sys

            print(f"\n[CRITICAL] {e}\n", file=sys.stderr)
            sys.exit(1)
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
    def config(self) -> dict:
        """
        .config is just .default_config + .custom_config merged together.

        Any new values should be added to custom_config.
        """
        if self._config is None:
            self._config = deep_merge(self.default_config, self.custom_config)
        return self._config

    @property
    def default_config(self) -> dict:
        """
        The default BBOT config (from `defaults.yml`).
        """
        global DEFAULT_CONFIG
        if DEFAULT_CONFIG is None:
            self.default_config = self.files_config.get_default_config()
            # ensure bbot home dir
            if "home" not in self.default_config:
                self.default_config["home"] = "~/.bbot"
        return DEFAULT_CONFIG

    @default_config.setter
    def default_config(self, value: dict):
        # we temporarily clear out the config so it can be refreshed if/when default_config changes
        global DEFAULT_CONFIG
        self._config = None
        DEFAULT_CONFIG = dict(value) if value else {}

    @property
    def custom_config(self) -> dict:
        """
        Custom BBOT config (from `~/.config/bbot/bbot.yml`)
        """
        # we temporarily clear out the config so it can be refreshed if/when custom_config changes
        self._config = None
        if self._custom_config is None:
            self.custom_config = self.files_config.get_custom_config()
        return self._custom_config

    @custom_config.setter
    def custom_config(self, value: dict):
        self._config = None
        self._custom_config = dict(value) if value else {}

    def no_secrets_config(self, config):
        """Return a copy of `config` with every `sensitive=True` field removed.

        Sensitivity is read from the per-field `json_schema_extra["sensitive"]`
        flag declared on `BBOTConfig` (and each module's `class Config`).
        Module-level redaction uses the composite schema built lazily by
        `MODULE_LOADER.config_schema`; if a key isn't covered by any schema
        (e.g. an unknown module), it passes through unchanged.
        """
        from .config.models import partition_sensitive_config

        return partition_sensitive_config(config, self._config_schema(), keep_sensitive=False)

    def secrets_only_config(self, config):
        """Return a copy of `config` containing only `sensitive=True` fields.

        Inverse of `no_secrets_config()`. Useful for splitting a merged config
        into a public `bbot.yml` and a private `secrets.yml`.
        """
        from .config.models import partition_sensitive_config

        return partition_sensitive_config(config, self._config_schema(), keep_sensitive=True)

    def _config_schema(self):
        """Resolve the runtime BBOTConfig schema (with per-module configs)."""
        try:
            from bbot.core.modules import MODULE_LOADER

            return MODULE_LOADER.config_schema
        except Exception:
            from .config.models import BBOTConfig

            return BBOTConfig

    def merge_custom(self, config):
        """Merge a config dict into the custom config."""
        self.custom_config = deep_merge(self.custom_config, dict(config) if config else {})

    def merge_default(self, config):
        """Merge a config dict into the default config."""
        self.default_config = deep_merge(self.default_config, dict(config) if config else {})

    def copy(self):
        """
        Return a semi-shallow copy of self. (`custom_config` is copied, but `default_config` stays the same)
        """
        core_copy = copy(self)
        core_copy._custom_config = deepcopy(self._custom_config) if self._custom_config else {}
        core_copy._config = None
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
