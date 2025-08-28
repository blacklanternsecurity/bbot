from .base import ModuleTestBase


class TestCRT_DB(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        class AsyncMock:
            async def fetch(self, *args, **kwargs):
                return [
                    {"name_value": "asdf.blacklanternsecurity.com"},
                    {"name_value": "zzzz.blacklanternsecurity.com"},
                ]

            async def close(self):
                pass

        async def mock_connect(*args, **kwargs):
            return AsyncMock()

        module_test.monkeypatch.setattr("asyncpg.connect", mock_connect)

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
