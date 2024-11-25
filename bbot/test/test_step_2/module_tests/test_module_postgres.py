import asyncio

from .base import ModuleTestBase


class TestPostgres(ModuleTestBase):
    targets = ["evilcorp.com"]
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        process = await asyncio.create_subprocess_exec(
            "docker",
            "run",
            "--name",
            "bbot-test-postgres",
            "--rm",
            "-e",
            "POSTGRES_PASSWORD=bbotislife",
            "-e",
            "POSTGRES_USER=postgres",
            "-p",
            "5432:5432",
            "-d",
            "postgres",
        )

        # wait for the container to start
        await self.wait_for_port_open(5432)

        if process.returncode != 0:
            self.log.error("Failed to start PostgreSQL server")

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
            process = await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-postgres", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Failed to stop PostgreSQL server: {stderr.decode()}")
