from .base import ModuleTestBase


class TestAjaxpro(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "ajaxpro"]
    exploit_headers = {"X-Ajaxpro-Method": "AddItem", "Content-Type": "text/json; charset=UTF-8"}
    exploit_response = """
    null; r.error = {"Message":"Constructor on type 'AjaxPro.Services.ICartService' not found.","Type":"System.MissingMethodException"};/*
    """

    async def setup_before_prep(self, module_test):
        # Simulate ajaxpro URL probe positive
        expect_args = {"method": "GET", "uri": "/ajaxpro/whatever.ashx"}
        respond_args = {"status": 200}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate ajaxpro URL probe negative
        expect_args = {"method": "GET", "uri": "/a/whatever.ashx"}
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate Vulnerability
        expect_args = {"method": "POST", "uri": "/ajaxpro/AjaxPro.Services.ICartService,AjaxPro.2.ashx"}
        respond_args = {"response_data": self.exploit_response}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        ajaxpro_url_detection = False
        ajaxpro_exploit_detection = False

        for e in events:
            if (
                e.type == "VULNERABILITY"
                and "Ajaxpro Deserialization RCE (CVE-2021-23758)" in e.data["description"]
                and "http://127.0.0.1:8888/ajaxpro/AjaxPro.Services.ICartService,AjaxPro.2.ashx"
                in e.data["description"]
            ):
                ajaxpro_exploit_detection = True

            if e.type == "TECHNOLOGY" and e.data["technology"] == "ajaxpro":
                ajaxpro_url_detection = True

        assert ajaxpro_url_detection, "Ajaxpro URL probe detection failed"
        assert ajaxpro_exploit_detection, "Ajaxpro Exploit detection failed"


class TestAjaxpro_httpdetect(TestAjaxpro):
    http_response_data = """
    <script src="ajax/AMBusinessFacades.AjaxUtils,AMBusinessFacades.ashx" type="text/javascript"></script><script type='text/javascript'>$(document).ready(function(){if (!(top.hasTouchScreen || (top.home && top.home.hasTouchScreen))){$('#ctl01_userid').trigger('focus').trigger('select');}});</script>
    <script type="text/javascript">
    if(typeof AjaxPro != "undefined") AjaxPro.noUtcTime = true;
    </script>

    <script type="text/javascript" src="/AcmeTest/ajax/AMBusinessFacades.NotificationsAjax,AMBusinessFacades.ashx"></script>
    <script type="text/javascript" src="/AcmeTest/ajax/AMBusinessFacades.ReportingAjax,AMBusinessFacades.ashx"></script>
    <script type="text/javascript" src="/AcmeTest/ajax/AMBusinessFacades.UsersAjax,AMBusinessFacades.ashx"></script>
    <script type="text/javascript" src="/AcmeTest/ajax/FAServerControls.FAPage,FAServerControls.ashx"></script>
    """

    async def setup_before_prep(self, module_test):
        # Simulate HTTP_RESPONSE detection
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": self.http_response_data}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        ajaxpro_httpresponse_detection = False
        for e in events:
            if e.type == "TECHNOLOGY" and e.data["technology"] == "ajaxpro":
                ajaxpro_httpresponse_detection = True
        assert ajaxpro_httpresponse_detection, "Ajaxpro HTTP_RESPONSE detection failed"
