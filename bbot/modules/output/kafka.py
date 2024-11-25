import json
from aiokafka import AIOKafkaProducer

from bbot.modules.output.base import BaseOutputModule


class Kafka(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a Kafka topic",
        "created_date": "2024-11-17",
        "author": "@TheTechromancer",
    }
    options = {
        "bootstrap_servers": "localhost:9092",
        "topic": "bbot_events",
    }
    options_desc = {
        "bootstrap_servers": "A comma-separated list of Kafka server addresses",
        "topic": "The Kafka topic to publish events to",
    }
    deps_pip = ["aiokafka~=0.12.0"]

    async def setup(self):
        self.bootstrap_servers = self.config.get("bootstrap_servers", "localhost:9092")
        self.topic = self.config.get("topic", "bbot_events")
        self.producer = AIOKafkaProducer(bootstrap_servers=self.bootstrap_servers)

        # Start the producer
        await self.producer.start()
        self.verbose("Kafka producer started successfully")
        return True

    async def handle_event(self, event):
        event_json = event.json()
        event_data = json.dumps(event_json).encode("utf-8")
        while 1:
            try:
                await self.producer.send_and_wait(self.topic, event_data)
                break
            except Exception as e:
                self.warning(f"Error sending event to Kafka: {e}, retrying...")
                await self.helpers.sleep(1)

    async def cleanup(self):
        # Stop the producer
        await self.producer.stop()
        self.verbose("Kafka producer stopped successfully")
