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

    def handle_event(self, event):

        wappalyzer = Wappalyzer.latest()
        split_headers = event.data["response-header"].split("\r\n")
        header_dict = {}

        for i in split_headers:
            if len(i) > 0 and ":" in i:
                header_dict[i.split(":")[0].lower()] = i.split(":")[1].lstrip()

        w = WebPage(url=event.data["url"], html=event.data.get("response-body", ""), headers=header_dict)
        res_set = wappalyzer.analyze(w)
        for res in res_set:

            self.emit_event({"technology": res.lower(), "url": event.data["url"]}, "TECHNOLOGY", event)
