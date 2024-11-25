import json
import asyncio
from contextlib import suppress

from .base import ModuleTestBase


class TestRabbitMQ(ModuleTestBase):
    config_overrides = {
        "modules": {
            "rabbitmq": {
                "url": "amqp://guest:guest@localhost/",
                "queue": "bbot_events",
            }
        }
    }
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        import aio_pika

        # Start RabbitMQ
        await asyncio.create_subprocess_exec(
            "docker", "run", "-d", "--rm", "--name", "bbot-test-rabbitmq", "-p", "5672:5672", "rabbitmq:3-management"
        )

        # Wait for RabbitMQ to be ready
        while True:
            try:
                # Attempt to connect to RabbitMQ with a timeout
                connection = await aio_pika.connect_robust("amqp://guest:guest@localhost/")
                break  # Exit the loop if the connection is successful
            except Exception as e:
                with suppress(Exception):
                    await connection.close()
                self.log.verbose(f"Waiting for RabbitMQ to be ready: {e}")
                await asyncio.sleep(0.5)  # Wait a bit before retrying

        self.connection = connection
        self.channel = await self.connection.channel()
        self.queue = await self.channel.declare_queue("bbot_events", durable=True)

    async def check(self, module_test, events):
        try:
            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Collect events from RabbitMQ
            rabbitmq_events = []
            async with self.queue.iterator() as queue_iter:
                async for message in queue_iter:
                    async with message.process():
                        event_data = json.loads(message.body.decode("utf-8"))
                        rabbitmq_events.append(event_data)
                        if len(rabbitmq_events) >= len(events_json):
                            break

            rabbitmq_events.sort(key=lambda x: x["timestamp"])

            # Verify the events match
            assert events_json == rabbitmq_events, "Events do not match"

        finally:
            # Clean up: Close the RabbitMQ connection
            await self.connection.close()
            # Stop RabbitMQ container
            await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-rabbitmq", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
