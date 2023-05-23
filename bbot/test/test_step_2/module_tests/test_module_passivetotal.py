from .base import ModuleTestBase


class TestPassiveTotal(ModuleTestBase):
    config_overrides = {"modules": {"passivetotal": {"username": "jon@bls.fakedomain", "api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.passivetotal.org/v2/account/quota",
            json={"user": {"counts": {"search_api": 10}, "limits": {"search_api": 20}}},
        )
        module_test.httpx_mock.add_response(
            url="https://api.passivetotal.org/v2/enrichment/subdomains?query=blacklanternsecurity.com",
            json={"subdomains": ["asdf"]},
        )

    async def setup_after_prep(self, module_test):
        module_test.monkeypatch.setattr(module_test.scan.modules["passivetotal"], "abort_if", lambda e: False)

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
