from ..bbot_fixtures import *  # noqa: F401
from ..test_step_2.module_tests.base import ModuleTestBase


class Scope_test_blacklist(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx"]

    blacklist = ["127.0.0.1"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert not any(e.type == "URL" for e in events)


class Scope_test_whitelist(Scope_test_blacklist):
    blacklist = []
    whitelist = ["255.255.255.255"]
