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
        "username": "",
        "password": "",
        "collection_prefix": "",
    }
    options_desc = {
        "uri": "The URI of the MongoDB server",
        "database": "The name of the database to use",
        "username": "The username to use to connect to the database",
        "password": "The password to use to connect to the database",
        "collection_prefix": "Prefix the name of each collection with this string",
    }
    deps_pip = ["motor~=3.6.0"]

    async def setup(self):
        self.uri = self.config.get("uri", "mongodb://localhost:27017")
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")
        self.db_client = AsyncIOMotorClient(self.uri, username=self.username, password=self.password)

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
        for field_name, field in Event.model_fields.items():
            if "indexed" in field.metadata:
                unique = "unique" in field.metadata
                await self.events_collection.create_index([(field_name, 1)], unique=unique)
                self.verbose(f"Index created for field: {field_name} (unique={unique})")

        return True

    async def handle_event(self, event):
        event_json = event.json()
        event_pydantic = Event(**event_json)
        while 1:
            try:
                await self.events_collection.insert_one(event_pydantic.model_dump())
                break
            except Exception as e:
                self.warning(f"Error inserting event into MongoDB: {e}, retrying...")
                await self.helpers.sleep(1)

        if event.type == "SCAN":
            scan_json = Scan(**event.data_json).model_dump()
            existing_scan = await self.scans_collection.find_one({"id": event_pydantic.id})
            if existing_scan:
                await self.scans_collection.replace_one({"id": event_pydantic.id}, scan_json)
                self.verbose(f"Updated scan event with ID: {event_pydantic.id}")
            else:
                # Insert as a new scan if no existing scan is found
                await self.scans_collection.insert_one(event_pydantic.model_dump())
                self.verbose(f"Inserted new scan event with ID: {event_pydantic.id}")

            target_data = scan_json.get("target", {})
            target = Target(**target_data)
            existing_target = await self.targets_collection.find_one({"hash": target.hash})
            if existing_target:
                await self.targets_collection.replace_one({"hash": target.hash}, target.model_dump())
            else:
                await self.targets_collection.insert_one(target.model_dump())
