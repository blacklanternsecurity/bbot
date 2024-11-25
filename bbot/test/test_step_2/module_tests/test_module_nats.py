import json
import asyncio
from contextlib import suppress

from .base import ModuleTestBase


class TestNats(ModuleTestBase):
    config_overrides = {
        "modules": {
            "nats": {
                "servers": ["nats://localhost:4222"],
                "subject": "bbot_events",
            }
        }
    }
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        # Start NATS server
        await asyncio.create_subprocess_exec(
            "docker", "run", "-d", "--rm", "--name", "bbot-test-nats", "-p", "4222:4222", "nats:latest"
        )

        # Wait for NATS to be ready by checking the port
        await self.wait_for_port_open(4222)

        # Connect to NATS
        import nats

        try:
            self.nc = await nats.connect(["nats://localhost:4222"])
        except Exception as e:
            self.log.error(f"Error connecting to NATS: {e}")
            raise

        # Collect events from NATS
        self.nats_events = []

        async def message_handler(msg):
            event_data = json.loads(msg.data.decode("utf-8"))
            self.nats_events.append(event_data)

        await self.nc.subscribe("bbot_events", cb=message_handler)

    async def check(self, module_test, events):
        try:
            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            self.nats_events.sort(key=lambda x: x["timestamp"])

            # Verify the events match
            assert events_json == self.nats_events, "Events do not match"

        finally:
            with suppress(Exception):
                # Clean up: Stop the NATS client
                if self.nc.is_connected:
                    await self.nc.drain()
                await self.nc.close()
            # Stop NATS server container
            await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-nats", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
