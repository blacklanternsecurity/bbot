from .base import ModuleTestBase


class TestThreatminer(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.threatminer.org/v2/domain.php?q=blacklanternsecurity.com&rt=5",
            json={"results": ["asdf.blacklanternsecurity.com"]},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
