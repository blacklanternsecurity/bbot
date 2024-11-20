import time
import asyncio

from .base import ModuleTestBase


class TestMongo(ModuleTestBase):
    test_db_name = "bbot_test"
    test_collection_prefix = "test_"
    config_overrides = {
        "modules": {
            "mongo": {
                "database": test_db_name,
                "username": "bbot",
                "password": "bbotislife",
                "collection_prefix": test_collection_prefix,
            }
        }
    }

    async def setup_before_prep(self, module_test):

        await asyncio.create_subprocess_exec(
            "docker",
            "run",
            "--name",
            "bbot-test-mongo",
            "--rm",
            "-e",
            "MONGO_INITDB_ROOT_USERNAME=bbot",
            "-e",
            "MONGO_INITDB_ROOT_PASSWORD=bbotislife",
            "-p",
            "27017:27017",
            "-d",
            "mongo",
        )

        from motor.motor_asyncio import AsyncIOMotorClient

        # Connect to the MongoDB collection with retry logic
        while True:
            try:
                client = AsyncIOMotorClient("mongodb://localhost:27017", username="bbot", password="bbotislife")
                db = client[self.test_db_name]
                events_collection = db.get_collection(self.test_collection_prefix + "events")
                # Attempt a simple operation to confirm the connection
                await events_collection.count_documents({})
                break  # Exit the loop if connection is successful
            except Exception as e:
                print(f"Connection failed: {e}. Retrying in 5 seconds...")
                time.sleep(0.5)

        # Check that there are no events in the collection
        count = await events_collection.count_documents({})
        assert count == 0, "There are existing events in the database"

        # Close the MongoDB connection
        client.close()

    async def check(self, module_test, events):
        try:
            from bbot.models.pydantic import Event
            from motor.motor_asyncio import AsyncIOMotorClient

            events_json = [e.json() for e in events]
            events_json.sort(key=lambda x: x["timestamp"])

            # Connect to the MongoDB collection
            client = AsyncIOMotorClient("mongodb://localhost:27017", username="bbot", password="bbotislife")
            db = client[self.test_db_name]
            events_collection = db.get_collection(self.test_collection_prefix + "events")

            # make sure the collection has all the right indexes
            cursor = events_collection.list_indexes()
            indexes = await cursor.to_list(length=None)
            for field in Event._indexed_fields():
                assert any(field in index["key"] for index in indexes), f"Index for {field} not found"

            # Fetch all events from the collection
            cursor = events_collection.find({})
            db_events = await cursor.to_list(length=None)

            # make sure we have the same number of events
            assert len(events_json) == len(db_events)

            for db_event in db_events:
                # we currently don't store timestamps as datetime objects because mongodb has lower precision
                # assert isinstance(db_event["timestamp"], datetime)
                # assert isinstance(db_event["inserted_at"], datetime)
                assert isinstance(db_event["timestamp"], str)
                assert isinstance(db_event["inserted_at"], str)

            # Convert to Pydantic objects and dump them
            db_events_pydantic = [Event(**e).model_dump(exclude_none=True) for e in db_events]
            db_events_pydantic.sort(key=lambda x: x["timestamp"])

            # Find the main event with type DNS_NAME and data blacklanternsecurity.com
            main_event = next(
                (
                    e
                    for e in db_events_pydantic
                    if e.get("type") == "DNS_NAME" and e.get("data") == "blacklanternsecurity.com"
                ),
                None,
            )
            assert main_event is not None, "Main event with type DNS_NAME and data blacklanternsecurity.com not found"

            # Ensure it has the reverse_host attribute
            expected_reverse_host = "blacklanternsecurity.com"[::-1]
            assert (
                main_event.get("reverse_host") == expected_reverse_host
            ), f"reverse_host attribute is not correct, expected {expected_reverse_host}"

            # Events don't match exactly because the mongo ones have reverse_host and inserted_at
            assert events_json != db_events_pydantic
            for db_event in db_events_pydantic:
                db_event.pop("reverse_host")
                db_event.pop("inserted_at")
            # They should match after removing reverse_host
            assert events_json == db_events_pydantic, "Events do not match"

        finally:
            # Clean up: Delete all documents in the collection
            await events_collection.delete_many({})
            # Close the MongoDB connection
            client.close()
            await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-mongo", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
