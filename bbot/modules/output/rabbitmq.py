import json
import aio_pika

from bbot.modules.output.base import BaseOutputModule
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig


class RabbitMQ(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a RabbitMQ queue",
        "created_date": "2024-11-22",
        "author": "@TheTechromancer",
    }
    class Config(BaseModuleConfig):
        url: str = Field('amqp://guest:guest@localhost/', description='The RabbitMQ connection URL')
        queue: str = Field('bbot_events', description='The RabbitMQ queue to publish events to')
    deps_pip = ["aio_pika~=9.5.0"]

    async def setup(self):
        self.rabbitmq_url = self.config.get("url", "amqp://guest:guest@localhost/")
        self.queue_name = self.config.get("queue", "bbot_events")

        # Connect to RabbitMQ
        self.connection = await aio_pika.connect_robust(self.rabbitmq_url)
        self.channel = await self.connection.channel()

        # Declare the queue
        self.queue = await self.channel.declare_queue(self.queue_name, durable=True)
        self.verbose("RabbitMQ connection and queue setup successfully")
        return True

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
        await self.connection.close()
        self.verbose("RabbitMQ connection closed successfully")
