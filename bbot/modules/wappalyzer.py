from bbot.modules.base import BaseModule
from Wappalyzer import Wappalyzer, WebPage

import warnings

warnings.filterwarnings(
    "ignore",
    message="""Caught 'unbalanced parenthesis at position 119' compiling regex""",
    category=UserWarning,
)


class wappalyzer(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["TECHNOLOGY"]
    flags = ["active", "safe", "web-basic", "web-thorough"]
    meta = {
        "description": "Extract technologies from web responses",
    }
    deps_pip = ["python-Wappalyzer~=0.3.1", "aiohttp~=3.9.0b0"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None
    _max_event_handlers = 5

    async def setup(self):
        self.wappalyzer = await self.scan.run_in_executor(Wappalyzer.latest)
        return True

    async def handle_event(self, event):
        for res in await self.scan.run_in_executor(self.wappalyze, event.data):
            await self.emit_event(
                {"technology": res.lower(), "url": event.data["url"], "host": str(event.host)}, "TECHNOLOGY", event
            )

    def wappalyze(self, data):
        w = WebPage(url=data["url"], html=data.get("body", ""), headers=data.get("header-dict", {}))
        return self.wappalyzer.analyze(w)
