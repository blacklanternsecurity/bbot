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

        expect_args = {"method": "GET", "uri": re.compile(r"\/BA\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BAC\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACK\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACKU\*~1\*.*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACKUP\*~1\*/a.aspx$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACKUP~1\*$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACKUP~1\.Z\*/a.aspx$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACKUP~1\.ZI\*/a.aspx$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": re.compile(r"\/BACKUP~1\.ZIP\*/a.aspx$")}
        respond_args = {"response_data": "", "status": 400}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        for char in "BLSHAXCKUP":
            expect_args = {"method": "GET", "uri": re.compile(rf"\/\*{char}\*~1\*.*$")}
            respond_args = {"response_data": "", "status": 400}
            module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        for char in "ZIP":
            expect_args = {"method": "GET", "uri": re.compile(rf"\/\*~1\*{char}\*.*$")}
            respond_args = {"response_data": "", "status": 400}
            module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        vulnerabilityEmitted = False
        url_hintEmitted = False
        zip_findingEmitted = False
        for e in events:
            if e.type == "VULNERABILITY" and "iis-magic-url" not in e.tags:
                vulnerabilityEmitted = True
            if e.type == "URL_HINT" and e.data == "http://127.0.0.1:8888/BLSHAX~1":
                url_hintEmitted = True
            if e.type == "FINDING" and "Possible backup file (zip) in web root" in e.data["description"]:
                zip_findingEmitted = True

        assert vulnerabilityEmitted
        assert url_hintEmitted
        assert zip_findingEmitted
