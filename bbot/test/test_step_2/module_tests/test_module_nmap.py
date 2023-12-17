from .base import ModuleTestBase


class TestNmap(ModuleTestBase):
    targets = ["127.0.0.1/31"]
    config_overrides = {"modules": {"nmap": {"ports": "8888,8889"}}}

    async def setup_after_prep(self, module_test):
        # make sure our IP_RANGE / IP_ADDRESS filtering is working right
        # IPs within the target IP range should be rejected
        ip_event_1 = module_test.scan.make_event("127.0.0.0", source=module_test.scan.root_event)
        ip_event_1.scope_distance = 0
        assert (await module_test.module._event_postcheck(ip_event_1)) == (
            False,
            "it did not meet custom filter criteria: Skipping 127.0.0.0 because it is already included in 127.0.0.0/31",
        )
        # but ones outside should be accepted
        ip_event_2 = module_test.scan.make_event("127.0.0.3", source=module_test.scan.root_event)
        ip_event_2.scope_distance = 0
        assert (await module_test.module._event_postcheck(ip_event_2))[0] == True

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.data == "127.0.0.1:8888"])
        assert not any(e.data == "127.0.0.1:8889" for e in events)
