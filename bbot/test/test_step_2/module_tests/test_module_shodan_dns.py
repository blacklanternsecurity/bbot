from .base import ModuleTestBase


class TestShodan_DNS(ModuleTestBase):
    config_overrides = {"modules": {"shodan": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/api-info?key=asdf",
        )
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/dns/domain/blacklanternsecurity.com?key=asdf&page=1",
            json={
                "subdomains": [
                    "asdf",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/dns/domain/blacklanternsecurity.com?key=asdf&page=2",
            json={
                "subdomains": [
                    "www",
                ],
            },
        )
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {
                    "A": ["127.0.0.11"],
                },
                "www.blacklanternsecurity.com": {"A": ["127.0.0.22"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.33"]},
            }
        )

    def check(self, module_test, events):
        assert len([e for e in events if e.type == "DNS_NAME"]) == 3, "Failed to detect both subdomains"
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "www.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
