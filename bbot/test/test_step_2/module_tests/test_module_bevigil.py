import random

from .base import ModuleTestBase


class TestBeVigil(ModuleTestBase):
    module_name = "bevigil"
    config_overrides = {"modules": {"bevigil": {"api_key": "asdf", "urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://osint.bevigil.com/api/blacklanternsecurity.com/subdomains/",
            match_headers={"X-Access-Token": "asdf"},
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


class TestBeVigilMultiKey(TestBeVigil):
    api_keys = ["1234", "4321", "asdf", "fdsa"]
    random.shuffle(api_keys)
    config_overrides = {"modules": {"bevigil": {"api_key": api_keys, "urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://osint.bevigil.com/api/blacklanternsecurity.com/subdomains/",
            match_headers={"X-Access-Token": "fdsa"},
            json={
                "domain": "blacklanternsecurity.com",
                "subdomains": [
                    "asdf.blacklanternsecurity.com",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            match_headers={"X-Access-Token": "asdf"},
            url=f"https://osint.bevigil.com/api/blacklanternsecurity.com/urls/",
            json={"domain": "blacklanternsecurity.com", "urls": ["https://asdf.blacklanternsecurity.com"]},
        )
