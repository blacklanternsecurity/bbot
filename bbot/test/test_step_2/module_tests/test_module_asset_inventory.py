from .base import ModuleTestBase


class TestAsset_Inventory(ModuleTestBase):
    targets = ["127.0.0.1", "bbottest.notreal"]
    scan_name = "asset_inventory_test"
    config_overrides = {"dns_resolution": True, "internal_modules": {"nmap": {"ports": "9999"}}}
    modules_overrides = ["asset_inventory", "nmap", "sslcert"]

    async def setup_before_prep(self, module_test):
        module_test.mock_dns(
            {
                "1.0.0.127.in-addr.arpa": {"PTR": ["www.bbottest.notreal"]},
                "www.bbottest.notreal": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.1:9999" for e in events), "No open port found"
        assert any(e.data == "www.bbottest.notreal" for e in events), "No DNS name found"
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            content = f.read()
            assert "www.bbottest.notreal,,,127.0.0.1" in content
        filename = next(module_test.scan.home.glob("asset-inventory-ip-addresses-table*.txt"))
        with open(filename) as f:
            assert "127.0.0.0/16" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-domains-table*.txt"))
        with open(filename) as f:
            content = f.read()
            assert "bbottest.notreal" in content


class TestAsset_InventoryEmitPrevious(TestAsset_Inventory):
    config_overrides = {"dns_resolution": True, "output_modules": {"asset_inventory": {"use_previous": True}}}
    modules_overrides = ["asset_inventory"]

    def check(self, module_test, events):
        assert any(e.data == "www.bbottest.notreal:9999" for e in events), "No open port found"
        assert any(e.data == "www.bbottest.notreal" for e in events), "No DNS name found"
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            content = f.read()
            assert "www.bbottest.notreal,,,127.0.0.1" in content
        filename = next(module_test.scan.home.glob("asset-inventory-ip-addresses-table*.txt"))
        with open(filename) as f:
            assert "127.0.0.0/16" in f.read()
        filename = next(module_test.scan.home.glob("asset-inventory-domains-table*.txt"))
        with open(filename) as f:
            content = f.read()
            assert "bbottest.notreal" in content


class TestAsset_InventoryRecheck(TestAsset_Inventory):
    config_overrides = {
        "dns_resolution": True,
        "output_modules": {"asset_inventory": {"use_previous": True, "recheck": True}},
    }
    modules_overrides = ["asset_inventory"]

    def check(self, module_test, events):
        assert not any(e.type == "OPEN_TCP_PORT" for e in events), "Open port was emitted"
        assert any(e.data == "www.bbottest.notreal" for e in events), "No DNS name found"
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            content = f.read()
            assert "www.bbottest.notreal,,,127.0.0.1" in content
