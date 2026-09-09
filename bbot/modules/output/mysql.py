from bbot.modules.templates.sql import SQLTemplate
from bbot.core.config.models import BaseModuleConfig, Field


class MySQL(SQLTemplate):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a MySQL database",
        "created_date": "2024-11-13",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        username: str = Field("root", description="The username to connect to MySQL", sensitive=True)
        password: str = Field("bbotislife", description="The password to connect to MySQL", sensitive=True)
        host: str = Field("localhost", description="The server running MySQL")
        port: int = Field(3306, description="The port to connect to MySQL")
        database: str = Field("bbot", description="The database name to connect to")
        retries: int = Field(
            10, description="Number of times to retry connecting to the database (1 second between retries)"
        )

    deps_pip = ["sqlmodel", "aiomysql"]
    protocol = "mysql+aiomysql"

    async def create_database(self):
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        # Create the engine for the initial connection to the server
        initial_engine = create_async_engine(self.connection_string().rsplit("/", 1)[0])

        async with initial_engine.connect() as conn:
            # Check if the database exists
            result = await conn.execute(text(f"SHOW DATABASES LIKE '{self.database}'"))
            database_exists = result.scalar() is not None

            # Create the database if it does not exist
            if not database_exists:
                # Use aiomysql directly to create the database
                import aiomysql

                raw_conn = await aiomysql.connect(
                    user=self.username,
                    password=self.password,
                    host=self.host,
                    port=self.port,
                )
                try:
                    async with raw_conn.cursor() as cursor:
                        await cursor.execute(f"CREATE DATABASE {self.database}")
                finally:
                    await raw_conn.ensure_closed()
