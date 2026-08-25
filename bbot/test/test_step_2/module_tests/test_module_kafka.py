import json
import asyncio

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
        await self.start_container("bbot-test-zookeeper", "-p", "2181:2181", "zookeeper:3.9")

        # Wait for Zookeeper to be ready
        await self.wait_for_port_open(2181)

        # Start Kafka using wurstmeister/kafka
        await self.start_container(
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

        # Wait for Kafka to be ready
        await self.wait_for_port_open(9092)

        await asyncio.sleep(1)

    async def check(self, module_test, events):
        from aiokafka import AIOKafkaConsumer

        self.consumer = AIOKafkaConsumer(
            "bbot_events",
            bootstrap_servers="localhost:9092",
            group_id="test_group",
            auto_offset_reset="earliest",
        )

        try:
            # inside the try: a failure here must still tear the containers down,
            # otherwise they hold port 9092 and every retry fails to bind it
            await self.consumer.start()

            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Collect events from Kafka with a timeout to prevent CI hangs
            kafka_events = []

            async def _consume():
                async for msg in self.consumer:
                    event_data = json.loads(msg.value.decode("utf-8"))
                    kafka_events.append(event_data)
                    if len(kafka_events) >= len(events_json):
                        break

            await asyncio.wait_for(_consume(), timeout=30)

            kafka_events.sort(key=lambda x: x["timestamp"])

            # Verify the events match
            assert events_json == kafka_events, "Events do not match"

        finally:
            # Clean up: Stop the Kafka consumer
            if hasattr(self, "consumer") and not self.consumer._closed:
                await self.consumer.stop()
            # Stop Kafka and Zookeeper containers
            await self.stop_container("bbot-test-kafka")
            await self.stop_container("bbot-test-zookeeper")
