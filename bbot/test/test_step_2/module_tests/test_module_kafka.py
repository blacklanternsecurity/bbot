import json
import asyncio

from bbot.test.worker import wait_for_container

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
        # KRaft mode: one broker, no zookeeper. The native image is ~150MB
        # against ~785MB for wurstmeister/kafka plus zookeeper, and CI pulls
        # cold on every run.
        await self.start_container(
            "bbot-test-kafka",
            "-e",
            "KAFKA_NODE_ID=1",
            "-e",
            "KAFKA_PROCESS_ROLES=broker,controller",
            "-e",
            "KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093",
            "-e",
            "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092",
            "-e",
            "KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER",
            "-e",
            "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT",
            "-e",
            "KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093",
            "-e",
            "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1",
            "-e",
            "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1",
            "-e",
            "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1",
            "-e",
            "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0",
            "-p",
            "9092:9092",
            "apache/kafka-native:4.1.2",
        )

        from aiokafka import AIOKafkaProducer

        # an open port is not a usable broker; probe a real produce round-trip.
        # separate topic so the one under assertion stays untouched.
        async def connect():
            producer = AIOKafkaProducer(bootstrap_servers="localhost:9092")
            await producer.start()
            try:
                await producer.send_and_wait("bbot_readiness", b"probe")
            finally:
                await producer.stop()

        await wait_for_container("Kafka", connect)

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
            await self.stop_container("bbot-test-kafka")
