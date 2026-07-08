from .base import ModuleTestBase


class TestCertspotter(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        for t in self.targets:
            module_test.blasthttp_mock.add_response(
                url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names",
                json=[{"dns_names": ["*.asdf.blacklanternsecurity.com"]}],
            )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestCertspotterPaginated(ModuleTestBase):
    module_name = "certspotter"
    config_overrides = {"modules": {"certspotter": {"api_key": "test_key"}}}

    base_url = "https://api.certspotter.com/v1/issuances"

    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        await module_test.mock_dns(
            {
                "page1.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "also-page1.blacklanternsecurity.com": {"A": ["127.0.0.2"]},
                "page2.blacklanternsecurity.com": {"A": ["127.0.0.3"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url=f"{self.base_url}?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names",
            json=[
                {"id": 100, "dns_names": ["page1.blacklanternsecurity.com"]},
                {"id": 200, "dns_names": ["also-page1.blacklanternsecurity.com"]},
            ],
        )
        module_test.blasthttp_mock.add_response(
            url=f"{self.base_url}?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names&after=200",
            json=[
                {"id": 300, "dns_names": ["page2.blacklanternsecurity.com"]},
            ],
        )
        module_test.blasthttp_mock.add_response(
            url=f"{self.base_url}?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names&after=300",
            json=[],
        )

    def check(self, module_test, events):
        dns_names = {e.data for e in events if e.type == "DNS_NAME"}
        assert "page1.blacklanternsecurity.com" in dns_names, "Missing page 1 result"
        assert "also-page1.blacklanternsecurity.com" in dns_names, "Missing page 1 second result"
        assert "page2.blacklanternsecurity.com" in dns_names, "Missing page 2 result"


class TestCertspotterRateLimited(ModuleTestBase):
    module_name = "certspotter"
    modules_overrides = ["certspotter"]

    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        module_test.blasthttp_mock.add_response(
            url="https://api.certspotter.com/v1/issuances?domain=blacklanternsecurity.com&include_subdomains=true&expand=dns_names",
            json={
                "code": "rate_limited",
                "message": "You have exceeded the domain search rate limit for the SSLMate CT Search API.",
            },
        )

    def check(self, module_test, events):
        assert not any(e.type == "DNS_NAME" and e.data != "blacklanternsecurity.com" for e in events), (
            "Should not produce subdomains from a rate-limited response"
        )
