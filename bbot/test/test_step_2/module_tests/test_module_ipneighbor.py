from .base import ModuleTestBase


class TestIPNeighbor(ModuleTestBase):
    targets = ["127.0.0.15", "www.bls.notreal"]
    config_overrides = {"scope_report_distance": 1, "dns_resolution": True, "scope_dns_search_distance": 2}

    async def setup_after_prep(self, module_test):
        module_test.mock_dns(
            {"3.0.0.127.in-addr.arpa": {"PTR": ["asdf.www.bls.notreal"]}, "asdf.www.bls.notreal": {"A": ["127.0.0.3"]}}
        )

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.3" for e in events)
        assert not any(e.data == "127.0.0.4" for e in events)
