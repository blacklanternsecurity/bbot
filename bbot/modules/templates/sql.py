from contextlib import suppress
from sqlmodel import SQLModel
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from bbot.db.sql.models import Event, Scan, Target
from bbot.modules.output.base import BaseOutputModule


class SQLTemplate(BaseOutputModule):
    meta = {"description": "SQL output module template"}
    options = {
        "database": "bbot",
        "username": "",
        "password": "",
        "host": "127.0.0.1",
        "port": 0,
    }
    options_desc = {
        "database": "The database to use",
        "username": "The username to use to connect to the database",
        "password": "The password to use to connect to the database",
        "host": "The host to use to connect to the database",
        "port": "The port to use to connect to the database",
    }

    protocol = ""

    async def setup(self):
        self.database = self.config.get("database", "bbot")
        self.username = self.config.get("username", "")
        self.password = self.config.get("password", "")
        self.host = self.config.get("host", "127.0.0.1")
        self.port = self.config.get("port", 0)

        await self.init_database()
        return True

    async def handle_event(self, event):
        event_obj = Event(**event.json()).validated

        async with self.async_session() as session:
            async with session.begin():
                # insert event
                session.add(event_obj)

                # if it's a SCAN event, create/update the scan and target
                if event_obj.type == "SCAN":
                    event_data = event_obj.get_data()
                    if not isinstance(event_data, dict):
                        raise ValueError(f"Invalid data for SCAN event: {event_data}")
                    scan = Scan(**event_data).validated
                    await session.merge(scan)  # Insert or update scan

                    target_data = event_data.get("target", {})
                    if not isinstance(target_data, dict):
                        raise ValueError(f"Invalid target for SCAN event: {target_data}")
                    target = Target(**target_data).validated
                    await session.merge(target)  # Insert or update target

                await session.commit()

    async def create_database(self):
        pass

    async def init_database(self):
        await self.create_database()

        # Now create the engine for the actual database
        self.engine = create_async_engine(self.connection_string())
        # Create a session factory bound to the engine
        self.async_session = sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

        # Use the engine directly to create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    def connection_string(self, mask_password=False):
        connection_string = f"{self.protocol}://"
        if self.username:
            password = self.password
            if mask_password:
                password = "****"
            connection_string += f"{self.username}:{password}"
        if self.host:
            connection_string += f"@{self.host}"
            if self.port:
                connection_string += f":{self.port}"
        if self.database:
            connection_string += f"/{self.database}"
        return connection_string

    async def cleanup(self):
        with suppress(Exception):
            await self.engine.dispose()
