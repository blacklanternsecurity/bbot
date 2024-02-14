from bbot.core.errors import RequestError

from bbot.modules.output.base import BaseOutputModule

class SPLUNK(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Send every event to a splunk instance through HTTP Event Collector"}
    options = {
        "url": "",
        "hectoken": "",
        "index": "",
        "source": "",
        "timeout": 10,
    }
    options_desc = {
        "url": "Web URL",
        "hectoken": "HEC Token",
        "index": "Index to send data to",
        "source": "Source path to be added to the metadata",
        "timeout": "HTTP timeout",
    }

    async def setup(self):
        self.url = self.config.get("url", "")
        self.source = self.config.get("source", "")
        self.index = self.config.get("index", "main")
        self.timeout = self.config.get("timeout", 10)
        self.headers = {}

        hectoken = self.config.get("hectoken", "")
        if hectoken:
            self.headers["Authorization"] = f"Splunk {hectoken}"
        if not self.url:
            self.warning("Must set URL")
            return False
        if not self.source:
            self.warning("Please provide a source")
        return True

    async def handle_event(self, event):
        while 1:
            try:
                data = {
                    "index": self.index,
                    "source": self.source,
                    "sourcetype": "_json",
                    "event": dict(event),
                }
                await self.helpers.request(
                    url=self.url,
                    method="POST",
                    headers=self.headers,
                    json=data,
                    raise_error=True,
                )
                break
            except RequestError as e:
                self.warning(f"Error sending {event}: {e}, retrying...")
                await self.helpers.sleep(1)
