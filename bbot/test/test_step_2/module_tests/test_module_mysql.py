import asyncio

from .base import ModuleTestBase


class TestMySQL(ModuleTestBase):
    targets = ["evilcorp.com"]
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        process = await asyncio.create_subprocess_exec(
            "docker",
            "run",
            "--name",
            "bbot-test-mysql",
            "--rm",
            "-e",
            "MYSQL_ROOT_PASSWORD=bbotislife",
            "-e",
            "MYSQL_DATABASE=bbot",
            "-p",
            "3306:3306",
            "-d",
            "mysql",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        # wait for the container to start
        await self.wait_for_port_open(3306)

        if process.returncode != 0:
            self.log.error(f"Failed to start MySQL server: {stderr.decode()}")

    async def check(self, module_test, events):
        import aiomysql

        # Connect to the MySQL database
        conn = await aiomysql.connect(user="root", password="bbotislife", db="bbot", host="localhost")

        try:
            async with conn.cursor() as cur:
                await cur.execute("SELECT * FROM event")
                events = await cur.fetchall()
                assert len(events) == 3, "No events found in MySQL database"

                await cur.execute("SELECT * FROM scan")
                scans = await cur.fetchall()
                assert len(scans) == 1, "No scans found in MySQL database"

                await cur.execute("SELECT * FROM target")
                targets = await cur.fetchall()
                assert len(targets) == 1, "No targets found in MySQL database"
        finally:
            conn.close()
            process = await asyncio.create_subprocess_exec(
                "docker", "stop", "bbot-test-mysql", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Failed to stop MySQL server: {stderr.decode()}")
