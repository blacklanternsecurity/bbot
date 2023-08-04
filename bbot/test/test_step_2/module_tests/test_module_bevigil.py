from .base import ModuleTestBase


class TestBeVigil(ModuleTestBase):
    config_overrides = {"modules": {"bevigil": {"api_key": "asdf", "urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://osint.bevigil.com/api/blacklanternsecurity.com/subdomains/",
            json={
                "domain": "blacklanternsecurity.com",
                "subdomains": [
                    "asdf.blacklanternsecurity.com",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url=f"https://osint.bevigil.com/api/blacklanternsecurity.com/urls/",
            json={"domain": "blacklanternsecurity.com", "urls": ["https://asdf.blacklanternsecurity.com"]},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "https://asdf.blacklanternsecurity.com/" for e in events), "Failed to detect url"
