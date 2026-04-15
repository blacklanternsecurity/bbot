import json
import nats
from bbot.modules.output.base import BaseOutputModule


class NATS(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a NATS subject",
        "created_date": "2024-11-22",
        "author": "@TheTechromancer",
    }
    options = {
        "servers": [],
        "subject": "bbot_events",
    }
    options_desc = {
        "servers": "A list of NATS server addresses",
        "subject": "The NATS subject to publish events to",
    }
    deps_pip = ["nats-py"]

    async def setup(self):
        self.servers = list(self.config.get("servers", []))
        if not self.servers:
            return False, "NATS servers are required"
        self.subject = self.config.get("subject", "bbot_events")

        # Connect to the NATS server
        try:
            self.nc = await nats.connect(self.servers)
        except Exception as e:
            import traceback

            return False, f"Error connecting to NATS: {e}\n{traceback.format_exc()}"
        self.verbose("NATS client connected successfully")
        return True

    async def handle_event(self, event):
        event_json = event.json()
        event_data = json.dumps(event_json).encode("utf-8")
        while 1:
            try:
                await self.nc.publish(self.subject, event_data)
                break
            except Exception as e:
                self.warning(f"Error sending event to NATS: {e}, retrying...")
                await self.helpers.sleep(1)

    async def cleanup(self):
        # Close the NATS connection
        await self.nc.close()
        self.verbose("NATS client disconnected successfully")
