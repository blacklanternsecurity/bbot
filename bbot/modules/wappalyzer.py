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
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Extract technologies from web responses",
        "created_date": "2022-04-15",
        "author": "@liquidsec",
    }
    deps_pip = ["python-Wappalyzer~=0.3.1", "aiohttp~=3.9.0b0"]
    # accept all events regardless of scope distance
    scope_distance_modifier = None
    _module_threads = 5

    @staticmethod
    def process_headers(headers):
        unique_headers = {}
        count = {}
        for k, v in headers.items():
            values = v if isinstance(v, list) else [v]
            for item in values:
                unique_key = k if k not in count else f"{k}_{count[k]}"
                while unique_key in unique_headers:
                    count[k] = count.get(k, 0) + 1
                    unique_key = f"{k}_{count[k]}"
                unique_headers[unique_key] = item
            count[k] = count.get(k, 0) + 1
        return unique_headers

    async def setup(self):
        self.wappalyzer = await self.helpers.run_in_executor(Wappalyzer.latest)
        return True

    async def handle_event(self, event):
        for res in await self.helpers.run_in_executor(self.wappalyze, event.data):
            res = res.lower()
            await self.emit_event(
                {"technology": res, "url": event.data["url"], "host": str(event.host)},
                "TECHNOLOGY",
                event,
                context=f"{{module}} analyzed HTTP_RESPONSE and identified {{event.type}}: {res}",
            )

    def wappalyze(self, data):
        # Convert dictionary of lists to a dictionary of strings
        header_dict = self.process_headers(data.get("header-dict", {}))
        w = WebPage(url=data["url"], html=data.get("body", ""), headers=header_dict)
        return self.wappalyzer.analyze(w)
