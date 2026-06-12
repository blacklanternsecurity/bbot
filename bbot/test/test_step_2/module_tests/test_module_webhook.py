import json
from bbot.test.mock_blasthttp import MockResponse

from .base import ModuleTestBase


class TestWebhook(ModuleTestBase):
    downstream_url = "https://blacklanternsecurity.fakedomain:1234/events"
    config_overrides = {
        "modules": {
            "webhook": {
                "url": downstream_url,
                "method": "PUT",
                "bearer": "auth_token",
                "username": "bbot_user",
                "password": "bbot_password",
            }
        }
    }

    def verify_data(self, j):
        return j.get("data") == "blacklanternsecurity.com" and j.get("type") == "DNS_NAME"

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
            return MockResponse(
                status_code=200,
            )

        module_test.blasthttp_mock.add_callback(custom_callback)
        module_test.blasthttp_mock.add_callback(custom_callback)
        module_test.blasthttp_mock.add_response(
            method="PUT", headers={"Authorization": "bearer auth_token"}, url=self.downstream_url
        )

    def check(self, module_test, events):
        assert self.got_event is True
        assert self.headers_correct is True
        assert self.method_correct is True
        assert self.url_correct is True
