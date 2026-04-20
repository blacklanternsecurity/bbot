from .base import ModuleTestBase


class TestAffiliates(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"dns": {"minimal": False, "filter_ptrs": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "8.8.8.8.in-addr.arpa": {"PTR": ["dns.google"]},
                "dns.google": {"A": ["8.8.8.8"], "NS": ["ns1.zdns.google"]},
                "ns1.zdns.google": {"A": ["1.2.3.4"]},
            }
        )

    def check(self, module_test, events):
        filename = next(module_test.scan.home.glob("affiliates-table*.txt"))
        with open(filename) as f:
            assert "zdns.google" in f.read()
