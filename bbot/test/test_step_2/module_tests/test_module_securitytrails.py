from .base import ModuleTestBase


class TestSecurityTrails(ModuleTestBase):
    config_overrides = {"modules": {"securitytrails": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/ping?apikey=asdf",
        )
        module_test.httpx_mock.add_response(
            url="https://api.securitytrails.com/v1/domain/blacklanternsecurity.com/subdomains?apikey=asdf",
            json={
                "subdomains": [
                    "asdf",
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
