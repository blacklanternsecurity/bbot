from .base import ModuleTestBase

import dns.rrset


class TestDNSCAA(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]
    config_overrides = {
        "scope_report_distance": 1,
    }

    async def setup_after_prep(self, module_test):
        old_resolve_fn = module_test.scan.helpers.dns.resolve_raw

        async def resolve_raw(query, **kwargs):
            if query == "blacklanternsecurity.notreal" and kwargs.get("type", "").upper() == "CAA":
                return (
                    (
                        (
                            "CAA",
                            dns.rrset.from_text_list(
                                query, 1, "IN", "CAA", ['0 iodef "https://caa.blacklanternsecurity.notreal"']
                            ),
                        ),
                        (
                            "CAA",
                            dns.rrset.from_text_list(
                                query, 1, "IN", "CAA", ['128 iodef "mailto:caa@blacklanternsecurity.notreal"']
                            ),
                        ),
                        ("CAA", dns.rrset.from_text_list(query, 1, "IN", "CAA", ['0 issue "comodoca.com"'])),
                        (
                            "CAA",
                            dns.rrset.from_text_list(
                                query, 1, "IN", "CAA", ['1 issue "digicert.com; cansignhttpexchanges=yes"']
                            ),
                        ),
                        ("CAA", dns.rrset.from_text_list(query, 1, "IN", "CAA", ['0 issuewild "letsencrypt.org"'])),
                        (
                            "CAA",
                            dns.rrset.from_text_list(
                                query, 1, "IN", "CAA", ['128 issuewild "pki.goog; cansignhttpexchanges=yes"']
                            ),
                        ),
                    ),
                    (),
                )
            return await old_resolve_fn(query, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolve_raw", resolve_raw)

    def check(self, module_test, events):
        assert any(e.type == "DNS_NAME" and e.data == "comodoca.com" for e in events), "Failed to detect CA DNS name"
        assert any(e.type == "DNS_NAME" and e.data == "digicert.com" for e in events), "Failed to detect CA DNS name"
        assert any(
            e.type == "DNS_NAME" and e.data == "letsencrypt.org" for e in events
        ), "Failed to detect CA DNS name"
        assert any(e.type == "DNS_NAME" and e.data == "pki.goog" for e in events), "Failed to detect CA DNS name"
        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "https://caa.blacklanternsecurity.notreal/" for e in events
        ), "Failed to detect URL"
        assert any(
            e.type == "EMAIL_ADDRESS" and e.data == "caa@blacklanternsecurity.notreal" for e in events
        ), "Failed to detect email address"
