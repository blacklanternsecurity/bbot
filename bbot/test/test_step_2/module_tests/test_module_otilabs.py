from .base import ModuleTestBase


class TestOtilabs(ModuleTestBase):
    config_overrides = {"modules": {"otilabs": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        # The shape of a real ?wait=1 response for a domain the API hadn't looked up before: every
        # source has finished, and only the live/historical split (live, live_count) is still being
        # computed, which BBOT doesn't need because it resolves the names itself.
        module_test.blasthttp_mock.add_response(
            url="https://domain-intelligence-api.p.rapidapi.com/domain/blacklanternsecurity.com/subdomains?wait=1",
            match_headers={"x-rapidapi-host": "domain-intelligence-api.p.rapidapi.com", "x-rapidapi-key": "asdf"},
            json={
                "count": 3,
                "live_count": None,
                "returned": 3,
                "subdomains": [
                    "asdf.blacklanternsecurity.com",
                    "zzzz.blacklanternsecurity.com",
                    "www.notblacklanternsecurity.com",
                ],
                "sources_used": [
                    "certspotter: 2 found",
                    "virustotal: 2 found",
                    "subfinder: 1 found",
                    "crt.sh: unavailable",
                    "liveness: enriching",
                ],
                "warnings": ["crt.sh: unavailable"],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect live subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect historical subdomain"
        assert not any(e.data == "www.notblacklanternsecurity.com" for e in events), (
            "Emitted a host outside the queried domain"
        )
