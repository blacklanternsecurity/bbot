from .base import ModuleTestBase


class TestIPNeighbor(ModuleTestBase):
    targets = ["127.0.0.15", "www.bls.notreal"]
    config_overrides = {"scope_report_distance": 1, "dns_resolution": True}

    def setup_after_prep(self, module_test):
        old_resolve_fn = module_test.scan.helpers.dns.resolve

        async def resolve(query, **kwargs):
            module_test.log.critical(f"{query}: {kwargs}")
            if query == "127.0.0.3" and kwargs.get("type", "").upper() == "PTR":
                return {"www.bls.notreal"}
            return await old_resolve_fn(query, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "resolve", resolve)

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.3" for e in events)
