from .base import ModuleTestBase


class TestVirusTotal(ModuleTestBase):
    config_overrides = {"modules": {"virustotal": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://www.virustotal.com/api/v3/domains/blacklanternsecurity.com/subdomains",
            json={
                "meta": {"count": 25, "cursor": "eyJsaW1pdCI6IDEwLCAib2Zmc2V0IjogMTB9"},
                "data": [
                    {
                        "attributes": {
                            "last_dns_records": [{"type": "A", "value": "168.62.180.225", "ttl": 3600}],
                            "whois": "Creation Date: 2013-07-30T20:14:50Z\nDNSSEC: unsigned\nDomain Name: BLACKLANTERNSECURITY.COM\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nName Server: NS01.DOMAINCONTROL.COM\nName Server: NS02.DOMAINCONTROL.COM\nRegistrar Abuse Contact Email: abuse@godaddy.com\nRegistrar Abuse Contact Phone: 480-624-2505\nRegistrar IANA ID: 146\nRegistrar URL: http://www.godaddy.com\nRegistrar WHOIS Server: whois.godaddy.com\nRegistrar: GoDaddy.com, LLC\nRegistry Domain ID: 1818679075_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2023-07-30T20:14:50Z\nUpdated Date: 2022-09-14T16:28:14Z",
                            "tags": [],
                            "popularity_ranks": {},
                            "last_dns_records_date": 1657734301,
                            "last_analysis_stats": {
                                "harmless": 0,
                                "malicious": 0,
                                "suspicious": 0,
                                "undetected": 86,
                                "timeout": 0,
                            },
                            "creation_date": 1375215290,
                            "reputation": 0,
                            "registrar": "GoDaddy.com, LLC",
                            "last_analysis_results": {},
                            "last_update_date": 1663172894,
                            "last_modification_date": 1657734301,
                            "tld": "com",
                            "categories": {},
                            "total_votes": {"harmless": 0, "malicious": 0},
                        },
                        "type": "domain",
                        "id": "asdf.blacklanternsecurity.com",
                        "links": {"self": "https://www.virustotal.com/api/v3/domains/asdf.blacklanternsecurity.com"},
                        "context_attributes": {"timestamp": 1657734301},
                    }
                ],
                "links": {
                    "self": "https://www.virustotal.com/api/v3/domains/blacklanternsecurity.com/subdomains?limit=10",
                    "next": "https://www.virustotal.com/api/v3/domains/blacklanternsecurity.com/subdomains?cursor=eyJsaW1pdCI6IDEwLCAib2Zmc2V0IjogMTB9&limit=10",
                },
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
