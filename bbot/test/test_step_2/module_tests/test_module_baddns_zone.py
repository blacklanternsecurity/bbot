import dns
from .base import ModuleTestBase


class BaseTestBaddns_zone(ModuleTestBase):
    modules_overrides = ["baddns_zone"]
    targets = ["bad.dns"]
    config_overrides = {"dns": {"minimal": False}}

    async def dispatchWHOIS(x):
        return None


class TestBaddns_zone_zonetransfer(BaseTestBaddns_zone):
    async def setup_after_prep(self, module_test):
        from baddns.lib.whoismanager import WhoisManager

        def from_xfr(*args, **kwargs):
            zone_text = """
@ 600 IN SOA ns.bad.dns. admin.bad.dns. (
    1   ; Serial
    3600   ; Refresh
    900   ; Retry
    604800   ; Expire
    86400 )  ; Minimum TTL
@ 600 IN NS ns.bad.dns.
@ 600 IN A 127.0.0.1
asdf 600 IN A 127.0.0.1
zzzz 600 IN AAAA dead::beef
"""
            zone = dns.zone.from_text(zone_text, origin="bad.dns.")
            return zone

        await module_test.mock_dns({"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}})
        module_test.monkeypatch.setattr("dns.zone.from_xfr", from_xfr)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any(e.data == "zzzz.bad.dns" for e in events), "Zone transfer failed (1)"
        assert any(e.data == "asdf.bad.dns" for e in events), "Zone transfer failed (2)"
        assert any(e.type == "FINDING" for e in events), "Failed to emit FINDING"
        assert any("baddns-zonetransfer" in e.tags for e in events), "Failed to add baddns tag"


class TestBaddns_zone_nsec(BaseTestBaddns_zone):
    targets = ["bad.com"]

    async def setup_after_prep(self, module_test):
        from baddns.lib.whoismanager import WhoisManager
        from baddns.lib.dnsmanager import DNSManager

        # NSEC records can't go through MockClient (hickory refuses zone-file NSEC parsing),
        # so we pass only non-NSEC data to mock_dns and handle NSEC via DNSManager monkeypatch.
        nsec_data = {
            "bad.com": ["asdf.bad.com"],
            "asdf.bad.com": ["zzzz.bad.com"],
            "zzzz.bad.com": ["xyz.bad.com"],
        }

        await module_test.mock_dns(
            {
                "bad.com": {"A": ["127.0.0.5"]},
            }
        )

        original_do_resolve = DNSManager.do_resolve
        original_dispatch = DNSManager.dispatchDNS

        async def patched_do_resolve(self, target, rdatatype):
            if rdatatype == "NSEC" and target in nsec_data:
                return nsec_data[target]
            return await original_do_resolve(self, target, rdatatype)

        async def patched_dispatch(self, omit_types=[]):
            await original_dispatch(self, omit_types=omit_types)
            if "NSEC" not in omit_types and self.target in nsec_data:
                self.answers["NSEC"] = nsec_data[self.target]

        module_test.monkeypatch.setattr(DNSManager, "do_resolve", patched_do_resolve)
        module_test.monkeypatch.setattr(DNSManager, "dispatchDNS", patched_dispatch)
        module_test.monkeypatch.setattr(WhoisManager, "dispatchWHOIS", self.dispatchWHOIS)

    def check(self, module_test, events):
        assert any(e.data == "zzzz.bad.com" for e in events), "NSEC Walk Failed (1)"
        assert any(e.data == "xyz.bad.com" for e in events), "NSEC Walk Failed (2)"
        assert any(e.type == "FINDING" for e in events), "Failed to emit FINDING"
        assert any("baddns-nsec" in e.tags for e in events), "Failed to add baddns tag"
