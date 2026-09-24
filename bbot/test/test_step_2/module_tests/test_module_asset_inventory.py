from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_SSL_HOSTPORT, HTTPSERVER_SSL_PORT


class TestAsset_Inventory(ModuleTestBase):
    targets = ["127.0.0.1", "bbottest.notreal"]
    scan_name = "asset_inventory_test"
    config_overrides = {"dns": {"minimal": False}, "modules": {"portscan": {"ports": f"{HTTPSERVER_SSL_PORT}"}}}
    modules_overrides = ["asset_inventory", "portscan", "sslcert"]

    # Mocked masscan output. The port here is what the module "discovers", so it
    # has to match the port the assertions expect, which moves per xdist worker.
    masscan_output = f"""{{   "ip": "127.0.0.1",   "timestamp": "1680197558", "ports": [ {{"port": {HTTPSERVER_SSL_PORT}, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 54}} ] }}"""

    async def setup_after_prep(self, module_test):
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
        assert any(e.data == HTTPSERVER_SSL_HOSTPORT for e in events), "No open port found"
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

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        # use_previous=True reads the asset-inventory.csv left behind by a
        # prior scan of the same name. Relying on TestAsset_Inventory to have
        # produced it makes this test order-dependent, which does not survive
        # xdist: sibling tests can run in any order, and on any worker. Seed
        # the file instead so the test stands on its own.
        scan_home = module_test.scan.home
        scan_home.mkdir(parents=True, exist_ok=True)
        with open(scan_home / "asset-inventory.csv", "w") as f:
            f.write("Host,Provider,IP(s),Status,Open Ports,Risk Rating,Findings,Description\n")
            f.write(f"www.bbottest.notreal,,127.0.0.1,Active,{HTTPSERVER_SSL_PORT},,,\n")

    def check(self, module_test, events):
        assert any(e.data == f"www.bbottest.notreal:{HTTPSERVER_SSL_PORT}" for e in events), "No open port found"
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
