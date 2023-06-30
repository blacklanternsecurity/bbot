from .base import ModuleTestBase


class TestAsset_Inventory(ModuleTestBase):
    targets = ["8.8.8.8"]
    scan_name = "asset_inventory_test"
    config_overrides = {"dns_resolution": True}
    modules_overrides = ["asset_inventory", "speculate", "sslcert"]

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" for e in events), "No open port found"
        assert any(e.type == "DNS_NAME" for e in events), "No DNS name found"
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            assert "8.8.8.8,,8.8.8.8" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-ip-addresses-table*.txt"))
        with open(filename) as f:
            assert "8.8.0.0/16" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-domains-table*.txt"))
        with open(filename) as f:
            assert "dns.google" in f.read()


class TestAsset_InventoryEmitPrevious(TestAsset_Inventory):
    config_overrides = {"dns_resolution": True, "output_modules": {"asset_inventory": {"use_previous": True}}}
    modules_overrides = ["asset_inventory"]

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" for e in events), "No open port found"
        assert any(e.type == "DNS_NAME" for e in events), "No DNS name found"
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            assert "8.8.8.8,,8.8.8.8" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-ip-addresses-table*.txt"))
        with open(filename) as f:
            assert "8.8.0.0/16" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-domains-table*.txt"))
        with open(filename) as f:
            assert "dns.google" in f.read()
