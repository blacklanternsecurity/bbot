import httpx

from .base import ModuleTestBase


class TestDiscord(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/cookie.aspx", "http://127.0.0.1:8888/cookie2.aspx", "foo.bar"]
    modules_overrides = ["discord", "excavate", "badsecrets", "httpx"]

    webhook_url = "https://discord.com/api/webhooks/1234/deadbeef-P-uF-asdf"
    config_overrides = {"modules": {"discord": {"webhook_url": webhook_url}}}

    def custom_setup(self, module_test):
        respond_args = {
            "response_data": '<html><body><p>Express Cookie Test<a href="ftp://asdf.foo.bar/asdf.txt"/></p></body></html>',
            "headers": {
                "set-cookie": "connect.sid=s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc; Path=/; Expires=Wed, 05 Apr 2023 04:47:29 GMT; HttpOnly"
            },
        }
        module_test.set_expect_requests(expect_args={"uri": "/cookie.aspx"}, respond_args=respond_args)
        module_test.set_expect_requests(expect_args={"uri": "/cookie2.aspx"}, respond_args=respond_args)
        module_test.request_count = 0

    async def setup_after_prep(self, module_test):
        self.custom_setup(module_test)

        def custom_response(request: httpx.Request):
            module_test.request_count += 1
            if module_test.request_count == 2:
                return httpx.Response(status_code=429, json={"retry_after": 0.01})
            else:
                return httpx.Response(status_code=200)

        module_test.httpx_mock.add_callback(custom_response, url=self.webhook_url)

    def check(self, module_test, events):
        vulns = [e for e in events if e.type == "VULNERABILITY"]
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1
        assert len(vulns) == 2
        assert module_test.request_count == 4
