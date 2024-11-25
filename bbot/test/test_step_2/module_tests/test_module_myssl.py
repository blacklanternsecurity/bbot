from .base import ModuleTestBase


class TestMySSL(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.module.abort_if = lambda e: False
        module_test.httpx_mock.add_response(
            url="https://myssl.com/api/v1/discover_sub_domain?domain=blacklanternsecurity.com",
            json={
                "code": 0,
                "data": [
                    {
                        "ip": "1.2.3.4",
                        "port": "443",
                        "tips": [],
                        "level": 2,
                        "title": "",
                        "domain": "asdf.blacklanternsecurity.com",
                        "is_ats": True,
                        "is_pci": False,
                        "server": "",
                        "is_tlcp": False,
                        "duration": 46,
                        "icon_url": "",
                        "is_sslvpn": False,
                        "level_str": "A",
                        "ip_location": "美国",
                        "is_enable_gm": False,
                        "evaluate_date": "2022-03-13T02:38:08Z",
                        "demotion_reason": [],
                        "ignore_trust_level": "A",
                        "meet_gm_double_cert_statndard": False,
                    }
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
