from .base import ModuleTestBase


class TestUrlScan(ModuleTestBase):
    config_overrides = {"modules": {"urlscan": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://urlscan.io/api/v1/search/?q=blacklanternsecurity.com",
            json={
                "results": [
                    {
                        "task": {
                            "visibility": "public",
                            "method": "api",
                            "domain": "asdf.blacklanternsecurity.com",
                            "apexDomain": "blacklanternsecurity.com",
                            "time": "2023-05-17T01:45:11.391Z",
                            "uuid": "c558b3b3-b274-4339-99ef-301eb043741f",
                            "url": "https://asdf.blacklanternsecurity.com/cna.html",
                        },
                        "stats": {
                            "uniqIPs": 6,
                            "uniqCountries": 3,
                            "dataLength": 926713,
                            "encodedDataLength": 332213,
                            "requests": 22,
                        },
                        "page": {
                            "country": "US",
                            "server": "GitHub.com",
                            "ip": "2606:50c0:8002::153",
                            "mimeType": "text/html",
                            "title": "Vulnerability Program | Black Lantern Security",
                            "url": "https://asdf.blacklanternsecurity.com/cna.html",
                            "tlsValidDays": 89,
                            "tlsAgeDays": 25,
                            "tlsValidFrom": "2023-04-21T19:16:58.000Z",
                            "domain": "asdf.blacklanternsecurity.com",
                            "apexDomain": "blacklanternsecurity.com",
                            "asnname": "FASTLY, US",
                            "asn": "AS54113",
                            "tlsIssuer": "R3",
                            "status": "200",
                        },
                        "_id": "c558b3b3-b274-4339-99ef-301eb043741f",
                        "_score": None,
                        "sort": [1684287911391, "c558b3b3-b274-4339-99ef-301eb043741f"],
                        "result": "https://urlscan.io/api/v1/result/c558b3b3-b274-4339-99ef-301eb043741f/",
                        "screenshot": "https://urlscan.io/screenshots/c558b3b3-b274-4339-99ef-301eb043741f.png",
                    }
                ]
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "https://asdf.blacklanternsecurity.com/cna.html" for e in events), "Failed to detect URL"
