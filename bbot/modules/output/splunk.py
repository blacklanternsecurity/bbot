from bbot.errors import WebError
from bbot.modules.output.base import BaseOutputModule
from bbot.core.config.models import BaseModuleConfig, Field


class Splunk(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Send every event to a splunk instance through HTTP Event Collector",
        "created_date": "2024-02-17",
        "author": "@w0Tx",
    }

    class Config(BaseModuleConfig):
        url: str = Field("", description="Web URL", sensitive=True)
        hectoken: str = Field("", description="HEC Token", sensitive=True)
        index: str = Field("", description="Index to send data to")
        source: str = Field("", description="Source path to be added to the metadata")
        timeout: int = Field(10, description="HTTP timeout")

    async def setup(self):
        self.url = self.config.get("url", "")
        self.source = self.config.get("source", "bbot")
        self.index = self.config.get("index", "main")
        self.timeout = self.config.get("timeout", 10)
        self.headers = {}

        hectoken = self.config.get("hectoken", "")
        if hectoken:
            self.headers["Authorization"] = f"Splunk {hectoken}"
        if not self.url:
            return False, "Must set URL"
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
                    "event": event.json(),
                }
                await self.helpers.request(
                    url=self.url,
                    method="POST",
                    headers=self.headers,
                    json=data,
                    raise_error=True,
                )
                break
            except WebError as e:
                self.warning(f"Error sending {event}: {e}, retrying...")
                await self.helpers.sleep(1)
