import asyncpg

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
        # first fetch raises "connection is closed"; subsequent fetches succeed
        async def fetch_succeed(self, *args, **kwargs):
            return [{"name_value": "reconnect.blacklanternsecurity.com"}]

        async def fetch_then_succeed(self, *args, **kwargs):
            self._closed = True
            raise asyncpg.InterfaceError("connection is closed")

        self.connect_count = 0

        async def mock_connect(*args, **kwargs):
            self.connect_count += 1
            conn = FakeAsyncpgConn()
            # first connection's fetch raises closed; second connection succeeds
            if self.connect_count == 1:
                conn.fetch = fetch_then_succeed.__get__(conn)
            else:
                conn.fetch = fetch_succeed.__get__(conn)
            return conn

        module_test.monkeypatch.setattr("asyncpg.connect", mock_connect)

    def check(self, module_test, events):
        assert self.connect_count >= 2, "Module did not reconnect after closed connection"
        assert any(e.data == "reconnect.blacklanternsecurity.com" for e in events), (
            "Failed to detect subdomain after reconnect"
        )
