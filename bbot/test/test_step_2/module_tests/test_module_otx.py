from .base import ModuleTestBase


class TestOTX(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://otx.alienvault.com/api/v1/indicators/domain/blacklanternsecurity.com/passive_dns",
            json={
                "passive_dns": [
                    {
                        "address": "2606:50c0:8000::153",
                        "first": "2021-10-28T20:23:08",
                        "last": "2022-08-24T18:29:49",
                        "hostname": "asdf.blacklanternsecurity.com",
                        "record_type": "AAAA",
                        "indicator_link": "/indicator/hostname/www.blacklanternsecurity.com",
                        "flag_url": "assets/images/flags/us.png",
                        "flag_title": "United States",
                        "asset_type": "hostname",
                        "asn": "AS54113 fastly",
                    }
                ]
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
