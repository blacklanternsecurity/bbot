from .base import ModuleTestBase


class TestNSEC(ModuleTestBase):
    targets = ["blacklanternsecurity.notreal"]

    async def setup_after_prep(self, module_test):
        next(iter(module_test.scan.target.events)).add_tag("ns-record")

        old_resolve_fn = module_test.scan.helpers.dns.resolve

        async def resolve(query, **kwargs):
            if query == "blacklanternsecurity.notreal" and kwargs.get("type", "").upper() == "NSEC":
                return {"asdf.blacklanternsecurity.notreal"}
            elif query == "asdf.blacklanternsecurity.notreal" and kwargs.get("type", "").upper() == "NSEC":
                return {"zzzz.blacklanternsecurity.notreal"}
            elif query == "zzzz.blacklanternsecurity.notreal" and kwargs.get("type", "").upper() == "NSEC":
                return {"blacklanternsecurity.notreal"}
            return await old_resolve_fn(query, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolve", resolve)

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.notreal" for e in events), "Failed to detect subdomain #1"
        assert any(e.data == "zzzz.blacklanternsecurity.notreal" for e in events), "Failed to detect subdomain #2"
