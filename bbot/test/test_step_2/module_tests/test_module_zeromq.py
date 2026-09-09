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
        self.context = zmq.asyncio.Context()
        self.socket = self.context.socket(zmq.SUB)
        self.socket.connect("tcp://localhost:5555")
        self.socket.setsockopt_string(zmq.SUBSCRIBE, "")

    async def setup_after_prep(self, module_test):
        self.zmq_events = []
        zeromq_module = module_test.scan.modules["zeromq"]
        original_send = zeromq_module.socket.send

        async def capturing_send(data, *args, **kwargs):
            self.zmq_events.append(json.loads(data.decode("utf-8")))
            return await original_send(data, *args, **kwargs)

        zeromq_module.socket.send = capturing_send

    def check(self, module_test, events):
        try:
            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])
            self.zmq_events.sort(key=lambda x: x["timestamp"])

            assert len(events_json) == len(self.zmq_events), (
                f"Event count mismatch: expected {len(events_json)}, got {len(self.zmq_events)}"
            )
            assert events_json == self.zmq_events, "Events do not match"
        finally:
            self.socket.close()
            self.context.term()
