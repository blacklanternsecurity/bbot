from urllib.parse import urlparse

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL
from bbot.modules.base import BaseModule


class TestAjaxpro(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "ajaxpro"]
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
                e.type == "FINDING"
                and "Ajaxpro Deserialization RCE (CVE-2021-23758)" in e.data["description"]
                and f"{HTTPSERVER_URL}/ajaxpro/AjaxPro.Services.ICartService,AjaxPro.2.ashx" in e.data["description"]
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


class TestAjaxpro_nowafpls_bypass(ModuleTestBase):
    """Ajaxpro should pad its exploit POST body via nowafpls when the URL is WAF-tagged and
    the WAF is bypassable; the resulting FINDING should carry the ``used-nowafpls`` tag."""

    targets = ["ajaxpro-bypass.test"]
    modules_overrides = ["http", "ajaxpro"]

    _exploit_response = (
        'null; r.error = {"Message":"Constructor on type \'AjaxPro.Services.ICartService\' not found.",'
        '"Type":"System.MissingMethodException"};'
    )

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        _name = "dummy_module"

        async def handle_event(self, event):
            if event.data != "ajaxpro-bypass.test":
                return
            url = self.scan.make_event(
                "http://ajaxpro-bypass.test/",
                "URL",
                parent=event,
                tags=["dir", "waf", "cloudflare", "in-scope", "status-200"],
            )
            if url is not None:
                await self.emit_event(url)

    async def setup_after_prep(self, module_test):
        from blasthttp.mock import MockResponse

        await module_test.mock_dns({"ajaxpro-bypass.test": {"A": ["127.0.0.1"]}})

        self.exploit_bodies: list[bytes] = []
        exploit_response = self._exploit_response

        def cb(request):
            method = request.method
            path = urlparse(str(request.url)).path
            body = request.content or b""
            if isinstance(body, str):
                body = body.encode()

            if method == "GET":
                if path.endswith("/ajaxpro/whatever.ashx"):
                    return MockResponse(status_code=200, text="ok")
                if path.endswith("/a/whatever.ashx"):
                    return MockResponse(status_code=404, text="not found")
                return MockResponse(status_code=200, text="ok")

            has_pad = body.startswith(b"__nowafpls_pad=") or b'"__nowafpls_pad"' in body
            has_malicious_script = b"%3Cscript" in body or b"<script" in body

            # nowafpls's own probe: baseline OK, unpadded malicious blocked (403), padded OK.
            if has_malicious_script and not has_pad:
                return MockResponse(status_code=403, text="Attention Required! | Cloudflare")

            if "ICartService" in path:
                self.exploit_bodies.append(body)
                return MockResponse(status_code=200, text=exploit_response)

            return MockResponse(status_code=200, text="Welcome to the application")

        module_test.blasthttp_mock.add_callback(callback=cb)
        module_test.scan.modules["dummy_module"] = self.DummyModule(module_test.scan)

    def check(self, module_test, events):
        assert any(b'"__nowafpls_pad"' in b for b in self.exploit_bodies), (
            f"Ajaxpro's exploit POST should carry the nowafpls JSON pad. Got exploit bodies: {self.exploit_bodies}"
        )
        finding = next(
            (
                e
                for e in events
                if e.type == "FINDING" and "Ajaxpro Deserialization RCE" in e.data.get("description", "")
            ),
            None,
        )
        assert finding is not None, "Ajaxpro RCE FINDING not emitted"
        assert "used-nowafpls" in finding.tags, (
            f"Ajaxpro finding should carry 'used-nowafpls' tag when the pad was applied. Tags: {list(finding.tags)}"
        )
