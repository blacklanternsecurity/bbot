import json
import asyncio
import logging
import websockets

from .base import ModuleTestBase

log = logging.getLogger("bbot.testing")

results = {"events": []}


async def websocket_handler(websocket, path):
    results["path"] = path
    async for message in websocket:
        results["events"].append(message)


# Define a coroutine for the server
async def server_coroutine():
    async with websockets.serve(websocket_handler, "127.0.0.1", 8765):
        await asyncio.Future()  # run forever


class TestWebsocket(ModuleTestBase):
    config_overrides = {"modules": {"websocket": {"url": "ws://127.0.0.1:8765/testing"}}}

    async def setup_before_prep(self, module_test):
        self.server_task = asyncio.create_task(server_coroutine())

    def check(self, module_test, events):
        assert results["path"] == "/testing"
        decoded_events = [json.loads(e) for e in results["events"]]
        assert any(e["type"] == "SCAN" for e in decoded_events)
        self.server_task.cancel()
