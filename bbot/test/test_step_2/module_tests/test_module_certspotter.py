from .base import ModuleTestBase


class TestCertspotter(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        for t in self.targets:
            module_test.httpx_mock.add_response(
                url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names",
                json=[{"dns_names": ["*.asdf.blacklanternsecurity.com"]}],
            )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
