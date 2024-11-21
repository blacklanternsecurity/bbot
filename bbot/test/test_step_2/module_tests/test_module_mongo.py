from .base import ModuleTestBase


class TestMongo(ModuleTestBase):
    test_db_name = "bbot_test"
    test_collection_name = "events_test"
    config_overrides = {"modules": {"mongo": {"database": test_db_name, "collection": test_collection_name}}}

    async def setup_before_module(self):
        from motor.motor_asyncio import AsyncIOMotorClient

        # Connect to the MongoDB collection
        client = AsyncIOMotorClient("mongodb://localhost:27017")
        db = client[self.test_db_name]
        collection = db.get_collection(self.test_collection_name)

        # Check that there are no events in the collection
        count = await collection.count_documents({})
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
            client = AsyncIOMotorClient("mongodb://localhost:27017")
            db = client[self.test_db_name]
            collection = db.get_collection(self.test_collection_name)

            # make sure the collection has all the right indexes
            cursor = collection.list_indexes()
            indexes = await cursor.to_list(length=None)
            for field in Event._indexed_fields():
                assert any(field in index["key"] for index in indexes), f"Index for {field} not found"

            # Fetch all events from the collection
            cursor = collection.find({})
            db_events = await cursor.to_list(length=None)

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

            # Compare the sorted lists
            assert len(events_json) == len(db_events_pydantic)
            # Events don't match exactly because the mongo ones have reverse_host
            assert events_json != db_events_pydantic
            for db_event in db_events_pydantic:
                db_event.pop("reverse_host")
            # They should match after removing reverse_host
            assert events_json == db_events_pydantic, "Events do not match"

        finally:
            # Clean up: Delete all documents in the collection
            await collection.delete_many({})
            # Close the MongoDB connection
            client.close()
