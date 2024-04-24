from .base import ModuleTestBase


class TestDNSCommonSRV(ModuleTestBase):
    config_overrides = {"dns_resolution": True}

    async def setup_after_prep(self, module_test):

        old_run_live = module_test.scan.helpers.run_live

        async def new_run_live(*command, check=False, text=True, **kwargs):
            if "massdns" in command[:2]:
                yield """{"name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","type":"SRV","class":"IN","status":"NOERROR","rx_ts":1713974911725326170,"data":{"answers":[{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."},{"ttl":86400,"type":"SRV","class":"IN","name":"_ldap._tcp.gc._msdcs.blacklanternsecurity.com.","data":"10 10 1720 asdf.blacklanternsecurity.com."}]},"flags":["rd","ra"],"resolver":"195.226.187.130:53","proto":"UDP"}"""
            else:
                async for _ in old_run_live(*command, check=False, text=True, **kwargs):
                    yield _

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", new_run_live)

        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "_ldap._tcp.gc._msdcs.blacklanternsecurity.com": {"SRV": ["0 100 3268 asdf.blacklanternsecurity.com"]},
                "asdf.blacklanternsecurity.com": {"A": ["1.2.3.5"]},
            }
        )

    def check(self, module_test, events):
        assert len(events) == 4
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "_ldap._tcp.gc._msdcs.blacklanternsecurity.com"
                and str(e.module) == "dnscommonsrv"
            ]
        ), "Failed to detect subdomain 1"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "asdf.blacklanternsecurity.com"
                and str(e.module) != "dnscommonsrv"
            ]
        ), "Failed to detect subdomain 2"
