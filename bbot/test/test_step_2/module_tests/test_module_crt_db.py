from .base import ModuleTestBase


class FakeAsyncpgConn:
    def __init__(self):
        self._closed = False
        self.fetch_calls = 0

    def is_closed(self):
        return self._closed

    async def fetch(self, *args, **kwargs):
        self.fetch_calls += 1
        return [
            {"name_value": "asdf.blacklanternsecurity.com"},
            {"name_value": "zzzz.blacklanternsecurity.com"},
        ]

    async def close(self):
        self._closed = True


class TestCRT_DB(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        async def mock_connect(*args, **kwargs):
            return FakeAsyncpgConn()

        module_test.monkeypatch.setattr("asyncpg.connect", mock_connect)

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestCRT_DB_Reconnect(ModuleTestBase):
    """
    Asyncpg connections drop mid-scan when the upstream Postgres restarts or idles us out.
    The module must reopen on the next call instead of staying broken for the rest of the scan.
    """

    targets = ["blacklanternsecurity.com", "evilcorp.com"]
    modules_overrides = ["crt_db"]

    async def setup_after_prep(self, module_test):
        async def fetch_succeed(self, *args, **kwargs):
            # args[1] is the query (domain); return a subdomain matching it
            query = args[1] if len(args) > 1 else "blacklanternsecurity.com"
            return [{"name_value": f"reconnect.{query}"}]

        async def fetch_then_fail(self, *args, **kwargs):
            self._closed = True
            raise ConnectionError("connection is closed")

        self.connect_count = 0

        async def mock_connect(*args, **kwargs):
            self.connect_count += 1
            conn = FakeAsyncpgConn()
            if self.connect_count == 1:
                conn.fetch = fetch_then_fail.__get__(conn)
            else:
                conn.fetch = fetch_succeed.__get__(conn)
            return conn

        module_test.monkeypatch.setattr("asyncpg.connect", mock_connect)

    def check(self, module_test, events):
        assert self.connect_count >= 2, "Module did not reconnect after closed connection"
        assert any(isinstance(e.data, str) and e.data.startswith("reconnect.") for e in events), (
            "Failed to detect subdomain after reconnect"
        )


class TestCRT_DB_OOM(ModuleTestBase):
    """When crt.sh's Postgres reports out-of-memory, the module must back off (error state) rather than hammer it."""

    module_name = "crt_db"
    modules_overrides = ["crt_db"]

    async def setup_after_prep(self, module_test):
        import asyncpg

        async def fetch_oom(self, *args, **kwargs):
            raise asyncpg.OutOfMemoryError("out of shared memory")

        async def mock_connect(*args, **kwargs):
            conn = FakeAsyncpgConn()
            conn.fetch = fetch_oom.__get__(conn)
            return conn

        module_test.monkeypatch.setattr("asyncpg.connect", mock_connect)

    def check(self, module_test, events):
        assert module_test.module.errored is True, "Module did not enter error state on Postgres out-of-memory"
