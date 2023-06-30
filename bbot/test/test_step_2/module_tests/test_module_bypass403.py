import re
from .base import ModuleTestBase


class TestBypass403(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/test"]
    modules_overrides = ["bypass403", "httpx"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/test..;/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1
        finding = findings[0]
        assert "http://127.0.0.1:8888/test..;/" in finding.data["description"]


class TestBypass403_aspnetcookieless(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/admin.aspx"]
    modules_overrides = ["bypass403", "httpx"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": re.compile(r"\/\([sS]\(\w+\)\)\/.+\.aspx")}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 2
        assert all("(S(X))/admin.aspx" in e.data["description"] for e in findings)


class TestBypass403_waf(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/test"]
    modules_overrides = ["bypass403", "httpx"]

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/test..;/"}
        respond_args = {"response_data": "The requested URL was rejected"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any(findings)
