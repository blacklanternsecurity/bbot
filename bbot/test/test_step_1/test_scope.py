from ..bbot_fixtures import *  # noqa: F401
from ..test_step_2.module_tests.base import ModuleTestBase


class TestScopeBaseline(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert len(events) == 7
        assert 2 == len([e for e in events if e.type == "SCAN"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and str(e.host) == "127.0.0.1"
                and e.scope_distance == 0
                and "seed" in e.tags
            ]
        )
        # we have two of these because the host module considers "always_emit" in its outgoing deduplication
        assert 2 == len(
            [
                e
                for e in events
                if e.type == "IP_ADDRESS"
                and e.data == "127.0.0.1"
                and e.scope_distance == 0
                and str(e.module) == "host"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "HTTP_RESPONSE"
                and str(e.host) == "127.0.0.1"
                and e.port == 8888
                and e.scope_distance == 0
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL" and str(e.host) == "127.0.0.1" and e.port == 8888 and e.scope_distance == 0
            ]
        )


class TestScopeBlacklist(TestScopeBaseline):
    blacklist = ["127.0.0.1"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert len(events) == 2
        assert not any(e.type == "URL" for e in events)
        assert not any(str(e.host) == "127.0.0.1" for e in events)


class TestScopeCidrWithSeeds(ModuleTestBase):
    """
    Test that when we have a CIDR as the target and DNS names as seeds,
    only the DNS names that resolve to IPs within the CIDR should be detected as in-scope.
    """

    # Seeds: DNS names that will be tested
    seeds = ["inscope.example.com", "outscope.example.com"]
    # Target: CIDR that defines the scope
    targets = ["192.168.1.0/24"]
    modules_overrides = ["dnsresolve"]

    async def setup_before_prep(self, module_test):
        # Mock DNS so that:
        # - inscope.example.com resolves to 192.168.1.10 (inside the /24)
        # - outscope.example.com resolves to 10.0.0.1 (outside the /24)
        # We do this before prep to ensure DNS mocking is ready before any resolution happens
        await module_test.mock_dns(
            {
                "inscope.example.com": {"A": ["192.168.1.10"]},
                "outscope.example.com": {"A": ["10.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        # Find the DNS_NAME events for our seeds
        inscope_events = [e for e in events if e.type == "DNS_NAME" and e.data == "inscope.example.com"]
        outscope_events = [e for e in events if e.type == "DNS_NAME" and e.data == "outscope.example.com"]

        assert len(inscope_events) == 1, "inscope.example.com should be detected"
        inscope_event = inscope_events[0]
        assert inscope_event.scope_distance == 0, (
            f"inscope.example.com should be in-scope (scope_distance=0), got {inscope_event.scope_distance}"
        )
        assert "192.168.1.10" in inscope_event.resolved_hosts, "inscope.example.com should resolve to 192.168.1.10"

        assert len(outscope_events) > 0, "outscope.example.com should be detected"
        outscope_event = outscope_events[0]
        assert outscope_event.scope_distance > 0, (
            f"outscope.example.com should be out-of-scope (scope_distance>0), got {outscope_event.scope_distance}"
        )
        assert "10.0.0.1" in outscope_event.resolved_hosts, "outscope.example.com should resolve to 10.0.0.1"
