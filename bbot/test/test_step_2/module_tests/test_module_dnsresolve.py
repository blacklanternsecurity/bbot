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
    config_overrides = {
        "dns": {"minimal": False, "filter_ptrs": True, "search_distance": 1},
        "scope": {"report_distance": 1, "search_distance": 0},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "1.0.168.192.in-addr.arpa": {"PTR": ["ptr-host.othercorp.com"]},
                "ptr-host.othercorp.com": {"A": ["192.168.0.1"]},
            }
        )

    def check(self, module_test, events):
        # the PTR-derived hostname should have the ptr tag
        ptr_events = [e for e in events if e.type == "DNS_NAME" and e.data == "ptr-host.othercorp.com"]
        assert len(ptr_events) == 1, f"Expected exactly 1 PTR-derived DNS_NAME, got {len(ptr_events)}"
        ptr_event = ptr_events[0]
        assert "ptr" in ptr_event.tags, f"PTR-derived event should have 'ptr' tag, has: {ptr_event.tags}"
        # it should NOT be promoted to in-scope (scope_distance should stay > 0)
        assert ptr_event.scope_distance > 0, (
            f"PTR-derived hostname should not be promoted to in-scope when filter_ptrs=true, "
            f"got scope_distance={ptr_event.scope_distance}"
        )
        assert "affiliate" in ptr_event.tags, (
            f"PTR-derived hostname should be tagged as affiliate, has: {ptr_event.tags}"
        )


class TestDNSResolveSharedNameserverDedup(ModuleTestBase):
    """
    Multiple in-scope parents that share the same NS/SOA records should not cause the
    shared nameserver hostname to be re-emitted once per parent. The dedup in
    DNSResolve.emit_dns_children must collapse identical (rdtype, child) pairs across
    parents, not key on parent host.
    """

    module_name = "dnsresolve"
    targets = ["domain-a.test", "domain-b.test", "domain-c.test"]
    config_overrides = {"dns": {"minimal": False}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        shared_ns = ["shared-ns1.cloudprovider.test.", "shared-ns2.cloudprovider.test."]
        shared_soa = ["shared-ns1.cloudprovider.test. admin.cloudprovider.test. 1 7200 3600 1209600 3600"]
        await module_test.mock_dns(
            {
                "domain-a.test": {"A": ["192.168.0.1"], "NS": shared_ns, "SOA": shared_soa},
                "domain-b.test": {"A": ["192.168.0.2"], "NS": shared_ns, "SOA": shared_soa},
                "domain-c.test": {"A": ["192.168.0.3"], "NS": shared_ns, "SOA": shared_soa},
                # resolve the shared nameservers so they keep the DNS_NAME type
                "shared-ns1.cloudprovider.test": {"A": ["192.168.99.1"]},
                "shared-ns2.cloudprovider.test": {"A": ["192.168.99.2"]},
            }
        )

    def check(self, module_test, events):
        from collections import Counter

        ns_counts = Counter(
            e.data for e in events if e.type in ("DNS_NAME", "DNS_NAME_UNRESOLVED") and str(e.module) == "NS"
        )
        soa_counts = Counter(
            e.data for e in events if e.type in ("DNS_NAME", "DNS_NAME_UNRESOLVED") and str(e.module) == "SOA"
        )

        # each shared nameserver hostname is referenced by all three in-scope parents
        # but should still be emitted exactly once
        assert ns_counts == {
            "shared-ns1.cloudprovider.test": 1,
            "shared-ns2.cloudprovider.test": 1,
        }, (
            f"Expected each shared NS hostname to be emitted exactly once across parents, "
            f"got: {dict(ns_counts)}. emit_dns_children dedup is keyed on "
            f"(parent_host, rdtype, child) instead of (rdtype, child)."
        )
        assert soa_counts == {"shared-ns1.cloudprovider.test": 1}, (
            f"Expected the shared SOA hostname to be emitted exactly once across parents, got: {dict(soa_counts)}."
        )


class TestDNSResolveFilterPTRsDisabled(ModuleTestBase):
    """Test that PTR-derived hostnames ARE promoted to in-scope when filter_ptrs is disabled."""

    module_name = "dnsresolve"
    targets = ["192.168.0.1"]
    config_overrides = {
        "dns": {"minimal": False, "filter_ptrs": False, "search_distance": 1},
        "scope": {"report_distance": 1, "search_distance": 0},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "1.0.168.192.in-addr.arpa": {"PTR": ["ptr-host.othercorp.com"]},
                "ptr-host.othercorp.com": {"A": ["192.168.0.1"]},
            }
        )

    def check(self, module_test, events):
        # with filter_ptrs disabled, PTR-derived hostname should be promoted to in-scope
        ptr_events = [e for e in events if e.type == "DNS_NAME" and e.data == "ptr-host.othercorp.com"]
        assert len(ptr_events) == 1, f"Expected exactly 1 PTR-derived DNS_NAME, got {len(ptr_events)}"
        ptr_event = ptr_events[0]
        assert "ptr" in ptr_event.tags, f"PTR-derived event should have 'ptr' tag, has: {ptr_event.tags}"
        # it SHOULD be promoted to in-scope
        assert ptr_event.scope_distance == 0, (
            f"PTR-derived hostname should be promoted to in-scope when filter_ptrs=false, "
            f"got scope_distance={ptr_event.scope_distance}"
        )
