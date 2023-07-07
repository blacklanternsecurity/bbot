from .base import ModuleTestBase


class TestCensys(ModuleTestBase):
    config_overrides = {"modules": {"censys": {"api_id": "api_id", "api_secret": "api_secret"}}}

    async def setup_before_prep(self, module_test):
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
            url="https://search.censys.io/api/v2/certificates/search",
            match_content=b'{"q": "names: blacklanternsecurity.com", "per_page": 100}',
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "query": "names: blacklanternsecurity.com",
                    "total": 196,
                    "duration_ms": 1046,
                    "hits": [
                        {
                            "parsed": {
                                "validity_period": {
                                    "not_before": "2021-11-18T00:09:46Z",
                                    "not_after": "2022-11-18T00:09:46Z",
                                },
                                "issuer_dn": "C=US, ST=Arizona, L=Scottsdale, O=GoDaddy.com\\, Inc., OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2",
                                "subject_dn": "CN=asdf.blacklanternsecurity.com",
                            },
                            "fingerprint_sha256": "590ad51b8db62925f0fd3f300264c6a36692e20ceec2b5a22e7e4b41c1575cdc",
                            "names": ["asdf.blacklanternsecurity.com", "asdf2.blacklanternsecurity.com"],
                        },
                    ],
                    "links": {"next": "NextToken", "prev": ""},
                },
            },
        )
        module_test.httpx_mock.add_response(
            url="https://search.censys.io/api/v2/certificates/search",
            match_content=b'{"q": "names: blacklanternsecurity.com", "per_page": 100, "cursor": "NextToken"}',
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "query": "names: blacklanternsecurity.com",
                    "total": 196,
                    "duration_ms": 1046,
                    "hits": [
                        {
                            "parsed": {
                                "validity_period": {
                                    "not_before": "2021-11-18T00:09:46Z",
                                    "not_after": "2022-11-18T00:09:46Z",
                                },
                                "issuer_dn": "C=US, ST=Arizona, L=Scottsdale, O=GoDaddy.com\\, Inc., OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2",
                                "subject_dn": "CN=zzzz.blacklanternsecurity.com",
                            },
                            "fingerprint_sha256": "590ad51b8db62925f0fd3f300264c6a36692e20ceec2b5a22e7e4b41c1575cdc",
                            "names": ["zzzz.blacklanternsecurity.com"],
                        },
                    ],
                    "links": {"next": "", "prev": ""},
                },
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect asdf subdomain"
        assert any(e.data == "asdf2.blacklanternsecurity.com" for e in events), "Failed to detect asdf2 subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect zzzz subdomain"
