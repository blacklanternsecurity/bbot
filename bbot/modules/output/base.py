from ..base import BaseModule


class BaseOutputModule(BaseModule):

    watched_events = ["*"]
    accept_dupes = True
    _priority = -100
    _type = "output"

    def _filter_event(self, event):
        return True

    @property
    def config(self):
        config = self.scan.config.get("output_modules", {}).get(self.name, {})
        if config is None:
            config = {}
        return config
