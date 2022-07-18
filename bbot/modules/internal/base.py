import logging

from bbot.modules.base import BaseModule


class BaseInternalModule(BaseModule):
    in_scope_only = False
    _type = "internal"
    # Priority, 1-5, lower numbers == higher priority
    _priority = 3

    @property
    def config(self):
        config = self.scan.config.get("internal_modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.internal.{self.name}")
        return self._log
