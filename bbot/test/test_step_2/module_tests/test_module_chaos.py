from .base import ModuleTestBase


class TestChaos(ModuleTestBase):
    config_overrides = {"modules": {"chaos": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/example.com",
            match_headers={"Authorization": "asdf"},
            json={"domain": "example.com", "subdomains": 65},
        )
        module_test.httpx_mock.add_response(
            url="https://dns.projectdiscovery.io/dns/blacklanternsecurity.com/subdomains",
            match_headers={"Authorization": "asdf"},
            json={
                "domain": "blacklanternsecurity.com",
                "subdomains": [
                    "*.asdf.cloud",
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.cloud.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
