from .base import ModuleTestBase


class TestCensys(ModuleTestBase):
    config_overrides = {"modules": {"censys": {"api_id": "api_id", "api_secret": "api_secret"}}}

    def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v1/account",
            json={
                "email": "info@blacklanternsecurity.com",
                "login": "nope",
                "first_login": "1917-08-03 20:03:55",
                "last_login": "1918-05-19 01:15:22",
                "quota": {"used": 26, "allowance": 250, "resets_at": "1919-06-03 16:30:32"},
            },
        )
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v1/search/certificates",
            match_content=b'{"query": "parsed.names: blacklanternsecurity.com", "page": 1, "fields": ["parsed.names"]}',
            json={
                "status": "ok",
                "metadata": {
                    "query": "parsed.names: blacklanternsecurity.com",
                    "count": 1,
                    "backend_time": 4465,
                    "page": 1,
                    "pages": 4,
                },
                "results": [
                    {
                        "parsed.names": [
                            "asdf.blacklanternsecurity.com",
                            "zzzz.blacklanternsecurity.com",
                        ]
                    },
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
