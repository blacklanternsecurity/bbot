import json
import zmq
import zmq.asyncio

from .base import ModuleTestBase


class TestZeroMQ(ModuleTestBase):
    config_overrides = {
        "modules": {
            "zeromq": {
                "zmq_address": "tcp://localhost:5555",
            }
        }
    }

    async def setup_before_prep(self, module_test):
        # Setup ZeroMQ context and socket
        self.context = zmq.asyncio.Context()
        self.socket = self.context.socket(zmq.SUB)
        self.socket.connect("tcp://localhost:5555")
        self.socket.setsockopt_string(zmq.SUBSCRIBE, "")

    async def check(self, module_test, events):
        try:
            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Collect events from ZeroMQ
            zmq_events = []
            while len(zmq_events) < len(events_json):
                msg = await self.socket.recv()
                event_data = json.loads(msg.decode("utf-8"))
                zmq_events.append(event_data)

            zmq_events.sort(key=lambda x: x["timestamp"])

            assert len(events_json) == len(zmq_events), "Number of events does not match"

            # Verify the events match
            assert events_json == zmq_events, "Events do not match"

        finally:
            # Clean up: Close the ZeroMQ socket
            self.socket.close()
            self.context.term()
