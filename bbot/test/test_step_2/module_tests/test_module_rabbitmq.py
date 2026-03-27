import json
import asyncio

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
        # Remove any leftover container from a previous failed run
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "rm",
            "-f",
            "bbot-test-rabbitmq",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.wait()

        # Start RabbitMQ
        await asyncio.create_subprocess_exec(
            "docker", "run", "-d", "--rm", "--name", "bbot-test-rabbitmq", "-p", "5672:5672", "rabbitmq:3-management"
        )

        # Wait for RabbitMQ to be ready by checking the port
        await self.wait_for_port_open(5672)

    async def check(self, module_test, events):
        import aio_pika

        connection = await aio_pika.connect_robust("amqp://guest:guest@localhost/")
        channel = await connection.channel()
        queue = await channel.declare_queue("bbot_events", durable=True)

        try:
            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Collect events from RabbitMQ
            rabbitmq_events = []
            async with queue.iterator() as queue_iter:
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
            await connection.close()
            # Stop RabbitMQ container
            process = await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-rabbitmq", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
