from .base import ModuleTestBase


class TestColumbus(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://columbus.elmasy.com/api/lookup/blacklanternsecurity.com?days=365",
            json=["asdf", "zzzz"],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
