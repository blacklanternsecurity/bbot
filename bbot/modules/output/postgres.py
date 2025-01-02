from bbot.modules.templates.sql import SQLTemplate


class Postgres(SQLTemplate):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a SQLite database",
        "created_date": "2024-11-08",
        "author": "@TheTechromancer",
    }
    options = {
        "username": "postgres",
        "password": "bbotislife",
        "host": "localhost",
        "port": 5432,
        "database": "bbot",
    }
    options_desc = {
        "username": "The username to connect to Postgres",
        "password": "The password to connect to Postgres",
        "host": "The server running Postgres",
        "port": "The port to connect to Postgres",
        "database": "The database name to connect to",
    }
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
