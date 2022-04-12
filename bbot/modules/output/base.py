from ..base import BaseModule


class BaseOutputModule(BaseModule):

    watched_events = ["*"]
    accept_dupes = True
    _priority = -100
    _type = "output"

    def _filter_event(self, event):
        return True
