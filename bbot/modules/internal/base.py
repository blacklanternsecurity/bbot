import logging
from ..base import BaseModule


class BaseInternalModule(BaseModule):
    _type = "internal"
    _priority = -50

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
