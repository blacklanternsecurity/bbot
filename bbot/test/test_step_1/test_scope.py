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
                and "target" in e.tags
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


class TestScopeWhitelist(TestScopeBlacklist):
    blacklist = []
    whitelist = ["255.255.255.255"]

    def check(self, module_test, events):
        assert len(events) == 4
        assert not any(e.type == "URL" for e in events)
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "IP_ADDRESS" and e.data == "127.0.0.1" and e.scope_distance == 1 and "target" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED"
                and str(e.host) == "127.0.0.1"
                and e.scope_distance == 1
                and "target" in e.tags
            ]
        )
