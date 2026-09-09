import json
import aio_pika

from bbot.modules.output.base import BaseOutputModule
from bbot.core.config.models import BaseModuleConfig, Field


class RabbitMQ(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a RabbitMQ queue",
        "created_date": "2024-11-22",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        url: str = Field("amqp://guest:guest@localhost/", description="The RabbitMQ connection URL", sensitive=True)
        queue: str = Field("bbot_events", description="The RabbitMQ queue to publish events to")

    deps_pip = ["aio_pika~=9.5.0"]

    async def setup(self):
        self.rabbitmq_url = self.config.get("url", "amqp://guest:guest@localhost/")
        self.queue_name = self.config.get("queue", "bbot_events")

        # Connect to RabbitMQ (retry in case the server is still starting)
        max_retries = 30
        for attempt in range(max_retries):
            try:
                self.connection = await aio_pika.connect_robust(self.rabbitmq_url)
                self.channel = await self.connection.channel()
                self.queue = await self.channel.declare_queue(self.queue_name, durable=True)
                self.verbose("RabbitMQ connection and queue setup successfully")
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    self.verbose(f"RabbitMQ not ready (attempt {attempt + 1}/{max_retries}): {e}")
                    await self.helpers.sleep(1)
                else:
                    self.error(f"Failed to connect to RabbitMQ after {max_retries} attempts: {e}")
                    return False

    async def handle_event(self, event):
        event_json = event.json()
        event_data = json.dumps(event_json).encode("utf-8")

        # Publish the message to the queue
        while 1:
            try:
                await self.channel.default_exchange.publish(
                    aio_pika.Message(body=event_data),
                    routing_key=self.queue_name,
                )
                break
            except Exception as e:
                self.error(f"Error publishing message to RabbitMQ: {e}, rerying...")
                await self.helpers.sleep(1)

    async def cleanup(self):
        # Close the connection
        if hasattr(self, "connection"):
            await self.connection.close()
            self.verbose("RabbitMQ connection closed successfully")
