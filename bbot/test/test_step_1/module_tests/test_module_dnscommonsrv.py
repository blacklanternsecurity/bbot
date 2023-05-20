from .base import ModuleTestBase


class TestDNSCommonSRV(ModuleTestBase):
    def setup_after_prep(self, module_test):
        old_resolve_fn = module_test.scan.helpers.dns.resolve

        async def resolve(query, **kwargs):
            if query == "_ldap._tcp.gc._msdcs.blacklanternsecurity.com" and kwargs.get("type", "").upper() == "SRV":
                return {"asdf.blacklanternsecurity.com"}
            return await old_resolve_fn(query, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolve", resolve)

    def check(self, module_test, events):
        assert any(
            e.data == "_ldap._tcp.gc._msdcs.blacklanternsecurity.com" for e in events
        ), "Failed to detect subdomain"
        assert not any(e.data == "_ldap._tcp.dc._msdcs.blacklanternsecurity.com" for e in events), "False positive"
