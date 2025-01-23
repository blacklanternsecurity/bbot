from .base import ModuleTestBase


class TestDNSCAA(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]
    modules_overrides = ["dnscaa", "speculate"]
    config_overrides = {
        "scope": {
            "report_distance": 1,
        }
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.notreal": {
                    "A": ["127.0.0.11"],
                    "CAA": [
                        '0 iodef "https://caa.blacklanternsecurity.notreal"',
                        '128 iodef "mailto:caa@blacklanternsecurity.notreal"',
                        '0 issue "comodoca.com"',
                        '1 issue "digicert.com; cansignhttpexchanges=yes"',
                        '0 issuewild "letsencrypt.org"',
                        '128 issuewild "pki.goog; cansignhttpexchanges=yes"',
                    ],
                },
                "caa.blacklanternsecurity.notreal": {"A": ["127.0.0.22"]},
                "comodoca.com": {
                    "A": ["127.0.0.33"],
                    "CAA": [
                        '0 iodef "https://caa.comodoca.com"',
                    ],
                },
                "caa.comodoca.com": {"A": ["127.0.0.33"]},
                "digicert.com": {"A": ["127.0.0.44"]},
                "letsencrypt.org": {"A": ["127.0.0.55"]},
                "pki.goog": {"A": ["127.0.0.66"]},
            }
        )

    def check(self, module_test, events):
        assert any(e.type == "DNS_NAME" and e.data == "comodoca.com" for e in events), "Failed to detect CA DNS name"
        assert any(e.type == "DNS_NAME" and e.data == "digicert.com" for e in events), "Failed to detect CA DNS name"
        assert any(e.type == "DNS_NAME" and e.data == "letsencrypt.org" for e in events), (
            "Failed to detect CA DNS name"
        )
        assert any(e.type == "DNS_NAME" and e.data == "pki.goog" for e in events), "Failed to detect CA DNS name"
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://caa.blacklanternsecurity.notreal/" for e in events
        ), "Failed to detect URL"
        assert any(e.type == "EMAIL_ADDRESS" and e.data == "caa@blacklanternsecurity.notreal" for e in events), (
            "Failed to detect email address"
        )
        # make sure we're not checking CAA records for out-of-scope hosts
        assert not any(str(e.host) == "caa.comodoca.com" for e in events)


class TestDNSCAAInScopeFalse(TestDNSCAA):
    config_overrides = {"scope": {"report_distance": 3}, "modules": {"dnscaa": {"in_scope_only": False}}}

    def check(self, module_test, events):
        assert any(str(e.host) == "caa.comodoca.com" for e in events)
