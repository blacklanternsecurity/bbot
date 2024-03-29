from .base import ModuleTestBase


class TestSublist3r(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://api.sublist3r.com/search.php?domain=blacklanternsecurity.com",
            json=["asdf.blacklanternsecurity.com", "zzzz.blacklanternsecurity.com"],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
