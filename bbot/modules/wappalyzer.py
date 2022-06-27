from .base import BaseModule
from Wappalyzer import Wappalyzer, WebPage

import warnings

warnings.filterwarnings(
    "ignore",
    message="""Caught 'unbalanced parenthesis at position 119' compiling regex""",
    category=UserWarning,
)


class wappalyzer(BaseModule):

    flags = ["active"]
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["TECHNOLOGY"]
    deps_pip = ["python-Wappalyzer"]

    def handle_event(self, event):

        wappalyzer = Wappalyzer.latest()
        split_headers = event.data["response-header"].split("\r\n")
        header_dict = {}

        for i in split_headers:
            if len(i) > 0 and ":" in i:
                header_dict[i.split(":")[0]] = i.split(":")[1].lstrip()

        w = WebPage(event.data["url"], html=event.data["response-body"], headers=header_dict)
        res_set = wappalyzer.analyze(w)
        for res in res_set:
            self.emit_event(f"[{event.data['url']}] {res}", "TECHNOLOGY", event, tags=["web"])
