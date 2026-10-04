from .base import ModuleTestBase


class TestOtilabs(ModuleTestBase):
    config_overrides = {"modules": {"otilabs": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://domain-intelligence-api.p.rapidapi.com/domain/blacklanternsecurity.com/subdomains",
            match_headers={"x-rapidapi-host": "domain-intelligence-api.p.rapidapi.com", "x-rapidapi-key": "asdf"},
            json={
                "domain": "blacklanternsecurity.com",
                "count": 3,
                "live_count": 1,
                "returned": 3,
                "subdomains": [
                    "asdf.blacklanternsecurity.com",
                    "zzzz.blacklanternsecurity.com",
                    "www.notblacklanternsecurity.com",
                ],
                "live": [{"host": "asdf.blacklanternsecurity.com", "ip": "1.2.3.4"}],
                "pools": [],
                "sources_used": ["certspotter: 2 found", "virustotal: 1 found"],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect live subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect historical subdomain"
        assert not any(e.data == "www.notblacklanternsecurity.com" for e in events), (
            "Emitted a host outside the queried domain"
        )
