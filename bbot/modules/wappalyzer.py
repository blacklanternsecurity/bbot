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
            if isinstance(v, list):
                for i, item in enumerate(v):
                    unique_key = f"{k}_{count[k]}" if k in count else k
                    while unique_key in unique_headers:
                        count[k] += 1
                        unique_key = f"{k}_{count[k]}"
                    unique_headers[unique_key] = item
                count[k] = count.get(k, 0) + len(v)
            else:
                if k in unique_headers:
                    unique_key = f"{k}_{count.get(k, 1)}"
                    count[k] = count.get(k, 1) + 1
                else:
                    unique_key = k
                    count[k] = 1
                unique_headers[unique_key] = v

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
