from .base import ModuleTestBase


class TestHackertarget(ModuleTestBase):
    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.hackertarget.com/hostsearch/?q=blacklanternsecurity.com",
            text="asdf.blacklanternsecurity.com\nzzzz.blacklanternsecurity.com",
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
