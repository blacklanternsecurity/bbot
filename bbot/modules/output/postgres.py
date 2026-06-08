from bbot.modules.templates.sql import SQLTemplate
from bbot.core.config.models import BaseModuleConfig, Field


class Postgres(SQLTemplate):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a SQLite database",
        "created_date": "2024-11-08",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        username: str = Field("postgres", description="The username to connect to Postgres", sensitive=True)
        password: str = Field("bbotislife", description="The password to connect to Postgres", sensitive=True)
        host: str = Field("localhost", description="The server running Postgres")
        port: int = Field(5432, description="The port to connect to Postgres")
        database: str = Field("bbot", description="The database name to connect to")
        retries: int = Field(
            10, description="Number of times to retry connecting to the database (1 second between retries)"
        )

    deps_pip = ["sqlmodel", "asyncpg"]
    protocol = "postgresql+asyncpg"

    async def create_database(self):
        import asyncpg
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        # Create the engine for the initial connection to the server
        initial_engine = create_async_engine(self.connection_string().rsplit("/", 1)[0])

        async with initial_engine.connect() as conn:
            # Check if the database exists
            result = await conn.execute(text(f"SELECT 1 FROM pg_database WHERE datname = '{self.database}'"))
            database_exists = result.scalar() is not None

            # Create the database if it does not exist
            if not database_exists:
                # Use asyncpg directly to create the database
                raw_conn = await asyncpg.connect(
                    user=self.username,
                    password=self.password,
                    host=self.host,
                    port=self.port,
                )
                try:
                    await raw_conn.execute(f"CREATE DATABASE {self.database}")
                finally:
                    await raw_conn.close()
