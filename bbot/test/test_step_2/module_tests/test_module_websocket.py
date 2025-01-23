import json
import asyncio
import logging
import websockets
from websockets.asyncio.server import serve

from .base import ModuleTestBase

log = logging.getLogger("bbot.testing")

results = {"events": []}


async def websocket_handler(websocket):
    results["path"] = websocket.request.path
    async for message in websocket:
        results["events"].append(message)


# Define a coroutine for the server
async def server_coroutine():
    async with serve(websocket_handler, "127.0.0.1", 8765) as server:
        await server.serve_forever()


class TestWebsocket(ModuleTestBase):
    config_overrides = {"modules": {"websocket": {"url": "ws://127.0.0.1:8765/testing"}}}

    async def setup_before_prep(self, module_test):
        self.server_task = asyncio.create_task(server_coroutine())

    def check(self, module_test, events):
        assert results["path"] == "/testing"
        decoded_events = [json.loads(e) for e in results["events"]]
        assert any(e["type"] == "SCAN" for e in decoded_events)
        self.server_task.cancel()
