from .base import ModuleTestBase


class TestIPNeighbor(ModuleTestBase):
    targets = ["127.0.0.15", "www.bls.notreal"]
    config_overrides = {"scope_report_distance": 1, "dns_resolution": True, "scope_dns_search_distance": 2}

    async def setup_after_prep(self, module_test):
        old_resolve_ip = module_test.scan.helpers.dns._resolve_ip
        old_resolve_hostname = module_test.scan.helpers.dns._resolve_hostname

        async def _resolve_ip(query, **kwargs):
            if query == "127.0.0.3":
                return [module_test.mock_record("asdf.www.bls.notreal", "PTR")], []
            return await old_resolve_ip(query, **kwargs)

        async def _resolve_hostname(query, **kwargs):
            if query == "asdf.www.bls.notreal" and kwargs.get("rdtype", "") == "A":
                return [module_test.mock_record("127.0.0.3", "A")], []
            return await old_resolve_hostname(query, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "_resolve_ip", _resolve_ip)
        module_test.monkeypatch.setattr(module_test.scan.helpers.dns, "_resolve_hostname", _resolve_hostname)

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.3" for e in events)
        assert not any(e.data == "127.0.0.4" for e in events)
