from .base import ModuleTestBase


class TestDNSCommonSRV(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]
    config_overrides = {"dns_resolution": True}

    async def setup_after_prep(self, module_test):
        module_test.mock_dns(
            {
                "_ldap._tcp.gc._msdcs.blacklanternsecurity.notreal": {
                    "SRV": ["0 100 3268 asdf.blacklanternsecurity.notreal"]
                },
                "asdf.blacklanternsecurity.notreal": {"A": "1.2.3.4"},
            }
        )

    def check(self, module_test, events):
        assert any(
            e.data == "_ldap._tcp.gc._msdcs.blacklanternsecurity.notreal" for e in events
        ), "Failed to detect subdomain"
        assert any(e.data == "asdf.blacklanternsecurity.notreal" for e in events), "Failed to detect subdomain"
        assert not any(e.data == "_ldap._tcp.dc._msdcs.blacklanternsecurity.notreal" for e in events), "False positive"
