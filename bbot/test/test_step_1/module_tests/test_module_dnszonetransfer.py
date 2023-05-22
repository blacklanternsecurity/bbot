import dns.zone
import dns.query
import dns.message

from .base import ModuleTestBase


class TestDNSZoneTransfer(ModuleTestBase):
    targets = ["blacklanternsecurity.fakedomain"]
    config_overrides = {"dns_resolution": True}

    async def setup_after_prep(self, module_test):
        old_resolve_fn = module_test.scan.helpers.dns._resolve_hostname

        async def _resolve_hostname(query, **kwargs):
            if query == "blacklanternsecurity.fakedomain" and kwargs.get("rdtype", "").upper() == "NS":
                return [module_test.mock_record("ns01.blacklanternsecurity.fakedomain", "NS")], []
            if query == "ns01.blacklanternsecurity.fakedomain" and kwargs.get("rdtype", "").upper() == "A":
                return [module_test.mock_record("127.0.0.1", "A")], []
            return await old_resolve_fn(query, **kwargs)

        def from_xfr(*args, **kwargs):
            zone_text = """
@ 600 IN SOA ns.blacklanternsecurity.fakedomain. admin.blacklanternsecurity.fakedomain. (
    1   ; Serial
    3600   ; Refresh
    900   ; Retry
    604800   ; Expire
    86400 )  ; Minimum TTL
@ 600 IN NS ns.blacklanternsecurity.fakedomain.
@ 600 IN A 127.0.0.1
asdf 600 IN A 127.0.0.1
zzzz 600 IN AAAA dead::beef
"""
            zone = dns.zone.from_text(zone_text, origin="blacklanternsecurity.fakedomain.")
            return zone

        module_test.monkeypatch.setattr("dns.zone.from_xfr", from_xfr)
        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "_resolve_hostname", _resolve_hostname)

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.fakedomain" for e in events), "Zone transfer failed"
        assert any(e.data == "zzzz.blacklanternsecurity.fakedomain" for e in events), "Zone transfer failed"
