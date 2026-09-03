from .base import ModuleTestBase


class TestMySQL(ModuleTestBase):
    targets = ["evilcorp.com"]
    skip_distro_tests = True

    async def setup_before_prep(self, module_test):
        await self.start_container(
            "bbot-test-mysql",
            "-e",
            "MYSQL_ROOT_PASSWORD=bbotislife",
            "-e",
            "MYSQL_DATABASE=bbot",
            "-p",
            "3306:3306",
            "mysql",
        )

        # wait for the container to start
        await self.wait_for_port_open(3306)

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
            await self.stop_container("bbot-test-mysql")
