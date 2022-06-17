import logging

from ..base import BaseModule


class BaseOutputModule(BaseModule):

    watched_events = ["*"]
    accept_dupes = True
    _priority = -100
    _type = "output"

    def _filter_event(self, e):
        # special "FINISHED" event
        if type(e) == str:
            if e == "FINISHED":
                return True
            else:
                return False
        if e._omit:
            return False
        if e._force_output:
            return True
        if e._internal:
            return False
        return True

    @property
    def config(self):
        config = self.scan.config.get("output_modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.output.{self.name}")
        return self._log
