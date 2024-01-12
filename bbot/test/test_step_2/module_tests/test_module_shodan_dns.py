from .base import ModuleTestBase


class TestShodan_DNS(ModuleTestBase):
    config_overrides = {"modules": {"shodan": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/api-info?key=asdf",
        )
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/dns/domain/blacklanternsecurity.com?key=asdf",
            json={
                "subdomains": [
                    "asdf",
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
