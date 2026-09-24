from .base import ModuleTestBase

from werkzeug.wrappers import Response
from bbot.test.worker import HTTPSERVER_URL


class TestWafw00f(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "wafw00f"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "WAF" and "LiteSpeed" in e.data["waf"] for e in events)


class TestWafw00f_noredirect(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "wafw00f"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"status": 301, "headers": {"Location": "/redirect"}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        expect_args = {"method": "GET", "uri": "/redirect"}
        respond_args = {"response_data": "Proudly powered by litespeed web server"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert not any(e.type == "WAF" for e in events)


class TestWafw00f_genericdetection(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "wafw00f"]

    async def setup_after_prep(self, module_test):
        def handler(request):
            if "SLEEP" in request.url:
                return Response("nope", status=403)
            return Response("yep")

        module_test.httpserver.expect_request("/").respond_with_handler(handler)

    def check(self, module_test, events):
        waf_events = [e for e in events if e.type == "WAF"]
        assert len(waf_events) == 1
        assert waf_events[0].data["waf"] == "generic detection"
