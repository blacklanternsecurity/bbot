import json
import asyncio
from contextlib import suppress

from .base import ModuleTestBase


class TestKafka(ModuleTestBase):
    config_overrides = {
        "modules": {
            "kafka": {
                "bootstrap_servers": "localhost:9092",
                "topic": "bbot_events",
            }
        }
    }
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        # Start Zookeeper
        await asyncio.create_subprocess_exec(
            "docker", "run", "-d", "--rm", "--name", "bbot-test-zookeeper", "-p", "2181:2181", "zookeeper:3.9"
        )

        # Wait for Zookeeper to be ready
        while True:
            try:
                # Attempt to connect to Zookeeper with a timeout
                reader, writer = await asyncio.wait_for(asyncio.open_connection("localhost", 2181), timeout=0.5)
                break  # Exit the loop if the connection is successful
            except Exception as e:
                self.log.verbose(f"Waiting for Zookeeper to be ready: {e}")
                await asyncio.sleep(0.5)  # Wait a bit before retrying
            finally:
                with suppress(Exception):
                    writer.close()
                    await writer.wait_closed()

        # Start Kafka using wurstmeister/kafka
        await asyncio.create_subprocess_exec(
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            "bbot-test-kafka",
            "--link",
            "bbot-test-zookeeper:zookeeper",
            "-e",
            "KAFKA_ZOOKEEPER_CONNECT=zookeeper:2181",
            "-e",
            "KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092",
            "-e",
            "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092",
            "-e",
            "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1",
            "-p",
            "9092:9092",
            "wurstmeister/kafka",
        )

        from aiokafka import AIOKafkaConsumer

        # Wait for Kafka to be ready
        while True:
            try:
                self.consumer = AIOKafkaConsumer(
                    "bbot_events",
                    bootstrap_servers="localhost:9092",
                    group_id="test_group",
                )
                await self.consumer.start()
                break  # Exit the loop if the consumer starts successfully
            except Exception as e:
                self.log.verbose(f"Waiting for Kafka to be ready: {e}")
                if hasattr(self, "consumer") and not self.consumer._closed:
                    await self.consumer.stop()
                await asyncio.sleep(0.5)  # Wait a bit before retrying

    async def check(self, module_test, events):
        try:
            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Collect events from Kafka
            kafka_events = []
            async for msg in self.consumer:
                event_data = json.loads(msg.value.decode("utf-8"))
                kafka_events.append(event_data)
                if len(kafka_events) >= len(events_json):
                    break

            kafka_events.sort(key=lambda x: x["timestamp"])

            # Verify the events match
            assert events_json == kafka_events, "Events do not match"

        finally:
            # Clean up: Stop the Kafka consumer
            if hasattr(self, "consumer") and not self.consumer._closed:
                await self.consumer.stop()
            # Stop Kafka and Zookeeper containers
            await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-kafka", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-zookeeper", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
