import zmq
import json

from bbot.modules.output.base import BaseOutputModule


class ZeroMQ(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a ZeroMQ socket (PUB)",
        "created_date": "2024-11-22",
        "author": "@TheTechromancer",
    }
    options = {
        "zmq_address": "",
    }
    options_desc = {
        "zmq_address": "The ZeroMQ socket address to publish events to (e.g. tcp://localhost:5555)",
    }

    async def setup(self):
        self.zmq_address = self.config.get("zmq_address", "")
        if not self.zmq_address:
            return False, "ZeroMQ address is required"
        self.context = zmq.asyncio.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.bind(self.zmq_address)
        self.verbose("ZeroMQ publisher socket bound successfully")
        return True

    async def handle_event(self, event):
        event_json = event.json()
        event_data = json.dumps(event_json).encode("utf-8")
        while 1:
            try:
                await self.socket.send(event_data)
                break
            except Exception as e:
                self.warning(f"Error sending event to ZeroMQ: {e}, retrying...")
                await self.helpers.sleep(1)

    async def cleanup(self):
        # Close the socket
        self.socket.close()
        self.context.term()
        self.verbose("ZeroMQ publisher socket closed successfully")
