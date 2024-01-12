import re

from .base import ModuleTestBase


class TestIIS_Shortnames(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "iis_shortnames"]
    config_overrides = {"modules": {"iis_shortnames": {"detect_only": False}}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.no_handler_status_code = 404

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive", "status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/*~1*/a.aspx"}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/B\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BL\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLS\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLSH\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLSHA\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BLSHAX\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        for char in "BLSHAX":
            expect_args = {"method": "GET", "uri": re.compile(rf"\/\*{char}\*~1\*.*$")}
            respond_args = {"response_data": "", "status": 400}
            module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        vulnerabilityEmitted = False
        url_hintEmitted = False
        for e in events:
            if e.type == "VULNERABILITY":
                vulnerabilityEmitted = True
            if e.type == "URL_HINT" and e.data == "http://127.0.0.1:8888/BLSHAX~1":
                url_hintEmitted = True

        assert vulnerabilityEmitted
        assert url_hintEmitted
