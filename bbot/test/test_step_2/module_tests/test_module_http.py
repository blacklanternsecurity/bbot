import json
import httpx

from .base import ModuleTestBase


class TestHTTP(ModuleTestBase):
    downstream_url = "https://blacklanternsecurity.fakedomain:1234/events"
    config_overrides = {
        "modules": {
            "http": {
                "url": downstream_url,
                "method": "PUT",
                "bearer": "auth_token",
                "username": "bbot_user",
                "password": "bbot_password",
            }
        }
    }

    def verify_data(self, j):
        return j["data"] == "blacklanternsecurity.com" and j["type"] == "DNS_NAME"

    async def setup_after_prep(self, module_test):
        self.got_event = False
        self.headers_correct = False
        self.method_correct = False
        self.url_correct = False

        async def custom_callback(request):
            j = json.loads(request.content)
            if request.url == self.downstream_url:
                self.url_correct = True
            if request.method == "PUT":
                self.method_correct = True
            if "Authorization" in request.headers:
                self.headers_correct = True
            if self.verify_data(j):
                self.got_event = True
            return httpx.Response(
                status_code=200,
            )

        module_test.httpx_mock.add_callback(custom_callback)
        module_test.httpx_mock.add_callback(custom_callback)
        module_test.httpx_mock.add_response(
            method="PUT", headers={"Authorization": "bearer auth_token"}, url=self.downstream_url
        )

    def check(self, module_test, events):
        assert self.got_event is True
        assert self.headers_correct is True
        assert self.method_correct is True
        assert self.url_correct is True


class TestHTTPSIEMFriendly(TestHTTP):
    modules_overrides = ["http"]
    config_overrides = {"modules": {"http": dict(TestHTTP.config_overrides["modules"]["http"])}}
    config_overrides["modules"]["http"]["siem_friendly"] = True

    def verify_data(self, j):
        return j["data"] == {"DNS_NAME": "blacklanternsecurity.com"} and j["type"] == "DNS_NAME"
