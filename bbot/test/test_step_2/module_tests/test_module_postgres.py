from .base import ModuleTestBase


class TestPostgres(ModuleTestBase):
    targets = ["evilcorp.com"]
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        await self.start_container(
            "bbot-test-postgres",
            "-e",
            "POSTGRES_PASSWORD=bbotislife",
            "-e",
            "POSTGRES_USER=postgres",
            "-p",
            "5432:5432",
            "postgres",
        )

        # wait for the container to start
        await self.wait_for_port_open(5432)

    async def check(self, module_test, events):
        import asyncpg

        # Connect to the PostgreSQL database
        conn = await asyncpg.connect(user="postgres", password="bbotislife", database="bbot", host="127.0.0.1")

        try:
            events = await conn.fetch("SELECT * FROM event")
            assert len(events) == 3, "No events found in PostgreSQL database"
            scans = await conn.fetch("SELECT * FROM scan")
            assert len(scans) == 1, "No scans found in PostgreSQL database"
            targets = await conn.fetch("SELECT * FROM target")
            assert len(targets) == 1, "No targets found in PostgreSQL database"
        finally:
            await conn.close()
            await self.stop_container("bbot-test-postgres")
