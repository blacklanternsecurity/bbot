from .base import ModuleTestBase


class TestDNSREsolve(ModuleTestBase):
    config_overrides = {"dns": {"minimal": False}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {
                    "A": ["192.168.0.7"],
                    "AAAA": ["::1"],
                    "CNAME": ["www.blacklanternsecurity.com"],
                },
                "www.blacklanternsecurity.com": {"A": ["192.168.0.8"]},
            }
        )

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "blacklanternsecurity.com"
                and "a-record" in e.tags
                and "aaaa-record" in e.tags
                and "cname-record" in e.tags
                and "private-ip" in e.tags
                and e.scope_distance == 0
                and "192.168.0.7" in e.resolved_hosts
                and "::1" in e.resolved_hosts
                and "www.blacklanternsecurity.com" in e.resolved_hosts
                and e.dns_children
                == {"A": {"192.168.0.7"}, "AAAA": {"::1"}, "CNAME": {"www.blacklanternsecurity.com"}}
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME"
                and e.data == "www.blacklanternsecurity.com"
                and "a-record" in e.tags
                and "private-ip" in e.tags
                and e.scope_distance == 0
                and "192.168.0.8" in e.resolved_hosts
                and e.dns_children == {"A": {"192.168.0.8"}}
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "IP_ADDRESS"
                and e.data == "192.168.0.7"
                and "private-ip" in e.tags
                and e.scope_distance == 1
            ]
        )


class TestDNSResolveFilterPTRs(ModuleTestBase):
    """Test that PTR-derived hostnames stay as affiliates when filter_ptrs is enabled (default)."""

    module_name = "dnsresolve"
    targets = ["192.168.0.1"]
    config_overrides = {"dns": {"minimal": False, "filter_ptrs": True, "search_distance": 1}, "scope": {"report_distance": 1, "search_distance": 0}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "1.0.168.192.in-addr.arpa": {"PTR": ["ptr-host.othercorp.com"]},
                "ptr-host.othercorp.com": {"A": ["192.168.0.1"]},
            }
        )

    def check(self, module_test, events):
        # the PTR-derived hostname should have the ptr tag
        ptr_events = [
            e for e in events if e.type == "DNS_NAME" and e.data == "ptr-host.othercorp.com"
        ]
        assert len(ptr_events) == 1, f"Expected exactly 1 PTR-derived DNS_NAME, got {len(ptr_events)}"
        ptr_event = ptr_events[0]
        assert "ptr" in ptr_event.tags, f"PTR-derived event should have 'ptr' tag, has: {ptr_event.tags}"
        # it should NOT be promoted to in-scope (scope_distance should stay > 0)
        assert ptr_event.scope_distance > 0, (
            f"PTR-derived hostname should not be promoted to in-scope when filter_ptrs=true, "
            f"got scope_distance={ptr_event.scope_distance}"
        )
        assert "affiliate" in ptr_event.tags, f"PTR-derived hostname should be tagged as affiliate, has: {ptr_event.tags}"


class TestDNSResolveFilterPTRsDisabled(ModuleTestBase):
    """Test that PTR-derived hostnames ARE promoted to in-scope when filter_ptrs is disabled."""

    module_name = "dnsresolve"
    targets = ["192.168.0.1"]
    config_overrides = {"dns": {"minimal": False, "filter_ptrs": False, "search_distance": 1}, "scope": {"report_distance": 1, "search_distance": 0}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "1.0.168.192.in-addr.arpa": {"PTR": ["ptr-host.othercorp.com"]},
                "ptr-host.othercorp.com": {"A": ["192.168.0.1"]},
            }
        )

    def check(self, module_test, events):
        # with filter_ptrs disabled, PTR-derived hostname should be promoted to in-scope
        ptr_events = [
            e for e in events if e.type == "DNS_NAME" and e.data == "ptr-host.othercorp.com"
        ]
        assert len(ptr_events) == 1, f"Expected exactly 1 PTR-derived DNS_NAME, got {len(ptr_events)}"
        ptr_event = ptr_events[0]
        assert "ptr" in ptr_event.tags, f"PTR-derived event should have 'ptr' tag, has: {ptr_event.tags}"
        # it SHOULD be promoted to in-scope
        assert ptr_event.scope_distance == 0, (
            f"PTR-derived hostname should be promoted to in-scope when filter_ptrs=false, "
            f"got scope_distance={ptr_event.scope_distance}"
        )
