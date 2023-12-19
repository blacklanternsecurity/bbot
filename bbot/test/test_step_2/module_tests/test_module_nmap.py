from .base import ModuleTestBase


class TestNmap(ModuleTestBase):
    targets = ["127.0.0.1/31"]
    config_overrides = {"modules": {"nmap": {"ports": "8888,8889"}}}

    async def setup_after_prep(self, module_test):
        # make sure our IP_RANGE / IP_ADDRESS filtering is working right
        # IPs within the target IP range should be rejected
        ip_event_1 = module_test.scan.make_event("127.0.0.0", source=module_test.scan.root_event)
        ip_event_1.scope_distance = 0
        ip_event_1_result = await module_test.module._event_postcheck(ip_event_1)
        assert ip_event_1_result[0] == False
        assert (
            "it did not meet custom filter criteria: skipping 127.0.0.0 because it is already included in 127.0.0.0/31"
            in ip_event_1_result[1]
        )
        # but ones outside should be accepted
        ip_event_2 = module_test.scan.make_event("127.0.0.3", source=module_test.scan.root_event)
        ip_event_2.scope_distance = 0
        assert (await module_test.module._event_postcheck(ip_event_2))[0] == True

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.data == "127.0.0.1:8888"])
        assert not any(e.data == "127.0.0.1:8889" for e in events)


class TestNmapAssetInventory(ModuleTestBase):
    targets = ["127.0.0.1/31"]
    config_overrides = {
        "modules": {"nmap": {"ports": "8888,8889"}},
        "output_modules": {"asset_inventory": {"use_previous": True}},
    }
    modules_overrides = ["nmap", "asset_inventory"]
    module_name = "nmap"
    scan_name = "nmap_test_asset_inventory"

    async def setup_after_prep(self, module_test):
        from bbot.scanner import Scanner

        first_scan_config = module_test.scan.config.copy()
        first_scan_config["output_modules"]["asset_inventory"]["use_previous"] = False
        first_scan = Scanner("127.0.0.1", name=self.scan_name, modules=["asset_inventory"], config=first_scan_config)
        await first_scan.async_start_without_generator()

        asset_inventory_output_file = first_scan.home / "asset-inventory.csv"
        assert "127.0.0.1," in open(asset_inventory_output_file).read()
        # make sure our IP_RANGE / IP_ADDRESS filtering is working right
        # IPs within the target IP range should not be rejected because asset_inventory.use_previous=true
        ip_event_1 = module_test.scan.make_event("127.0.0.0", source=module_test.scan.root_event)
        ip_event_1.scope_distance = 0
        assert (await module_test.module._event_postcheck(ip_event_1))[0] == True
        # but ones outside should be accepted
        ip_event_2 = module_test.scan.make_event("127.0.0.3", source=module_test.scan.root_event)
        ip_event_2.scope_distance = 0
        assert (await module_test.module._event_postcheck(ip_event_2))[0] == True

        ip_range_event = module_test.scan.make_event("127.0.0.1/31", source=module_test.scan.root_event)
        ip_range_event.scope_distance = 0
        ip_range_filter_result = await module_test.module._event_postcheck(ip_range_event)
        assert ip_range_filter_result[0] == False
        assert f"skipping IP_RANGE 127.0.0.0/31 because asset_inventory.use_previous=True" in ip_range_filter_result[1]

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.data == "127.0.0.1:8888"
                and e.source.data == "127.0.0.1"
                and str(e.source.module) == "asset_inventory"
            ]
        )
        assert not any(e.data == "127.0.0.1:8889" for e in events)
