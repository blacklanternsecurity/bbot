from bbot.modules.base import BaseModule
from Wappalyzer import Wappalyzer, WebPage

import warnings

warnings.filterwarnings(
    "ignore",
    message="""Caught 'unbalanced parenthesis at position 119' compiling regex""",
    category=UserWarning,
)


class wappalyzer(BaseModule):

    flags = ["active", "safe"]
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["TECHNOLOGY"]
    deps_pip = ["python-Wappalyzer"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None
    max_threads = 5

    def setup(self):
        self.wappalyzer = Wappalyzer.latest()
        return True

    def handle_event(self, event):
        for res in self.wappalyze(event.data):
            self.emit_event(
                {"technology": res.lower(), "url": event.data["url"], "host": str(event.host)}, "TECHNOLOGY", event
            )

    def wappalyze(self, data):
        w = WebPage(url=data["url"], html=data.get("response-body", ""), headers=data.get("header-dict", {}))
        return self.wappalyzer.analyze(w)
