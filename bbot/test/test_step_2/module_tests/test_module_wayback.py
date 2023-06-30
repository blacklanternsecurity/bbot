from .base import ModuleTestBase


class TestWayback(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original",
            json=[["original"], ["http://asdf.blacklanternsecurity.com"]],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
