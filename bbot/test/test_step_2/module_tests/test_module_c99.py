from .base import ModuleTestBase


class TestC99(ModuleTestBase):
    config_overrides = {"modules": {"c99": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.c99.nl/randomnumber?key=asdf&between=1,100&json",
            json={"success": True, "output": 65},
        )
        module_test.httpx_mock.add_response(
            url="https://api.c99.nl/subdomainfinder?key=asdf&domain=blacklanternsecurity.com&json",
            json={
                "success": True,
                "subdomains": [
                    {"subdomain": "asdf.blacklanternsecurity.com", "ip": "1.2.3.4", "cloudflare": True},
                ],
                "cached": True,
                "cache_time": "2023-05-19 03:13:05",
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
