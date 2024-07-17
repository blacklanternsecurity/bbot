import json
import asyncio
import websockets

from bbot.modules.output.base import BaseOutputModule


class Websocket(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to websockets", "created_date": "2022-04-15", "author": "@TheTechromancer"}
    options = {"url": "", "token": "", "preserve_graph": True}
    options_desc = {
        "url": "Web URL",
        "token": "Authorization Bearer token",
        "preserve_graph": "Preserve full chains of events in the graph (prevents orphans)",
    }

    async def setup(self):
        self.url = self.config.get("url", "")
        if not self.url:
            return False, "Must set URL"
        self.token = self.config.get("token", "")
        self._ws = None
        return True

    async def handle_event(self, event):
        event_json = event.json()
        await self.send(event_json)

    async def ws(self, rebuild=False):
        if self._ws is None or rebuild:
            kwargs = {"close_timeout": 0.5}
            if self.token:
                kwargs.update({"extra_headers": {"Authorization": f"Bearer {self.token}"}})
            verbs = ("Building", "Built")
            if rebuild:
                verbs = ("Rebuilding", "Rebuilt")
            self.debug(f"{verbs[0]} websocket connection to {self.url}")
            self._ws = await websockets.connect(self.url, **kwargs)
            self.debug(f"{verbs[1]} websocket connection to {self.url}")
        return self._ws

    async def send(self, message):
        rebuild = False
        while not self.scan.stopped:
            try:
                ws = await self.ws(rebuild=rebuild)
                message_str = json.dumps(message)
                self.debug(f"Sending message of length {len(message_str)}")
                await ws.send(message_str)
                rebuild = False
                break
            except Exception as e:
                self.warning(f"Error sending message: {e}, retrying")
                await asyncio.sleep(1)
                rebuild = True

    async def cleanup(self):
        if self._ws is not None:
            self.debug(f"Closing connection to {self.url}")
            await self._ws.close()
            self.debug(f"Closed connection to {self.url}")
        self._ws = None
