from .base import ModuleTestBase


class TestAsset_Inventory(ModuleTestBase):
    targets = ["127.0.0.1", "bbottest.notreal"]
    scan_name = "asset_inventory_test"
    config_overrides = {"dns": {"minimal": False}, "modules": {"portscan": {"ports": "9999"}}}
    modules_overrides = ["asset_inventory", "portscan", "sslcert"]

    masscan_output = """{   "ip": "127.0.0.1",   "timestamp": "1680197558", "ports": [ {"port": 9999, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54} ] }"""

    async def setup_before_prep(self, module_test):

        async def run_masscan(command, *args, **kwargs):
            if "masscan" in command[:2]:
                targets = open(command[11]).read().splitlines()
                yield "["
                for l in self.masscan_output.splitlines():
                    if "127.0.0.1/32" in targets:
                        yield self.masscan_output
                yield "]"
            else:
                async for l in module_test.scan.helpers.run_live(command, *args, **kwargs):
                    yield l

        module_test.monkeypatch.setattr(module_test.scan.helpers, "run_live", run_masscan)

        await module_test.mock_dns(
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
    config_overrides = {"dns": {"minimal": False}, "modules": {"asset_inventory": {"use_previous": True}}}
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
        "dns": {"minimal": False},
        "modules": {"asset_inventory": {"use_previous": True, "recheck": True}},
    }
    modules_overrides = ["asset_inventory"]

    def check(self, module_test, events):
        assert not any(e.type == "OPEN_TCP_PORT" for e in events), "Open port was emitted"
        assert any(e.data == "www.bbottest.notreal" for e in events), "No DNS name found"
        filename = next(module_test.scan.home.glob("asset-inventory.csv"))
        with open(filename) as f:
            content = f.read()
            assert "www.bbottest.notreal,,,127.0.0.1" in content
