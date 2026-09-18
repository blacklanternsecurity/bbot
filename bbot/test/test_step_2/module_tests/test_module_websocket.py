import json
import logging
from websockets.asyncio.server import serve

from .base import ModuleTestBase
from bbot.test.worker import WEBSOCKET_PORT

log = logging.getLogger("bbot.testing")

results = {"events": []}


async def websocket_handler(websocket):
    results["path"] = websocket.request.path
    async for message in websocket:
        results["events"].append(message)


class TestWebsocket(ModuleTestBase):
    config_overrides = {"modules": {"websocket": {"url": f"ws://127.0.0.1:{WEBSOCKET_PORT}/testing"}}}

    async def setup_before_prep(self, module_test):
        self.server = await serve(websocket_handler, "127.0.0.1", WEBSOCKET_PORT)

    async def _execute_scan(self, module_test):
        # shut down on the fixture's loop, which is the one that created the server
        try:
            await super()._execute_scan(module_test)
        finally:
            self.server.close()
            await self.server.wait_closed()

    def check(self, module_test, events):
        assert results["path"] == "/testing"
        decoded_events = [json.loads(e) for e in results["events"]]
        assert any(e["type"] == "SCAN" for e in decoded_events)
