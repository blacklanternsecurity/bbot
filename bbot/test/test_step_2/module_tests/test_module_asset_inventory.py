from .base import ModuleTestBase


class TestAsset_Inventory(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"dns_resolution": True}

    def check(self, module_test, events):
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            assert "8.8.8.8,,8.8.8.8" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-ip-addresses-table*.txt"))
        with open(filename) as f:
            assert "8.8.0.0/16" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-domains-table*.txt"))
        with open(filename) as f:
            assert "dns.google" in f.read()
