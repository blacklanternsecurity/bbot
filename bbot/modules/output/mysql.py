from bbot.modules.templates.sql import SQLTemplate


class MySQL(SQLTemplate):
    watched_events = ["*"]
    meta = {
        "description": "Output scan data to a MySQL database",
        "created_date": "2024-11-13",
        "author": "@TheTechromancer",
    }
    options = {
        "username": "root",
        "password": "bbotislife",
        "host": "localhost",
        "port": 3306,
        "database": "bbot",
    }
    options_desc = {
        "username": "The username to connect to MySQL",
        "password": "The password to connect to MySQL",
        "host": "The server running MySQL",
        "port": "The port to connect to MySQL",
        "database": "The database name to connect to",
    }
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
