from motor.motor_asyncio import AsyncIOMotorClient

from bbot.models.pydantic import Event, Scan, Target
from bbot.modules.output.base import BaseOutputModule


class Mongo(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a MongoDB database",
        "created_date": "2024-11-17",
        "author": "@TheTechromancer",
    }
    options = {
        "uri": "mongodb://localhost:27017",
        "database": "bbot",
        "collection_prefix": "",
    }
    options_desc = {
        "uri": "The URI of the MongoDB server",
        "database": "The name of the database to use",
        "collection_prefix": "Prefix each collection with this string",
    }
    deps_pip = ["motor~=3.6.0"]

    async def setup(self):
        self.uri = self.config.get("uri", "mongodb://localhost:27017")
        self.db_client = AsyncIOMotorClient(self.uri)

        # Ping the server to confirm a successful connection
        try:
            await self.db_client.admin.command("ping")
            self.verbose("MongoDB connection successful")
        except Exception as e:
            return False, f"Failed to connect to MongoDB: {e}"

        self.db_name = self.config.get("database", "bbot")
        self.db = self.db_client[self.db_name]
        self.collection_prefix = self.config.get("collection_prefix", "")
        self.events_collection = self.db[f"{self.collection_prefix}events"]
        self.scans_collection = self.db[f"{self.collection_prefix}scans"]
        self.targets_collection = self.db[f"{self.collection_prefix}targets"]

        # Build an index for each field in reverse_host and host
        for field in Event.model_fields:
            if "indexed" in field.metadata:
                unique = "unique" in field.metadata
                await self.collection.create_index([(field, 1)], unique=unique)
                self.verbose(f"Index created for field: {field}")

        return True

    async def handle_event(self, event):
        event_json = event.json()
        event_pydantic = Event(**event_json)
        await self.events_collection.insert_one(event_pydantic.model_dump())

        if event.type == "SCAN":
            scan_json = Scan.from_event(event).model_dump()
            existing_scan = await self.scans_collection.find_one({"uuid": event_pydantic.uuid})
            if existing_scan:
                await self.scans_collection.replace_one({"uuid": event_pydantic.uuid}, scan_json)
                self.verbose(f"Updated scan event with UUID: {event_pydantic.uuid}")
            else:
                # Insert as a new scan if no existing scan is found
                await self.scans_collection.insert_one(event_pydantic.model_dump())
                self.verbose(f"Inserted new scan event with UUID: {event_pydantic.uuid}")
