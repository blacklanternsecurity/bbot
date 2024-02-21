from .base import ModuleTestBase


class TestWafw00f(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wafw00f"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "WAF" and "LiteSpeed" in e.data["WAF"] for e in events)


class TestWafw00f_noredirect(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "wafw00f"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"status": 301, "headers": {"Location": "/redirect"}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = {"method": "GET", "uri": "/redirect"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert not any(e.type == "WAF" for e in events)
