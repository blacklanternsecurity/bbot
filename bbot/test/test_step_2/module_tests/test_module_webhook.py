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


class TestWebhookGivesUp(TestWebhook):
    """A webhook endpoint that always fails must not hang the scan; the module errors out instead."""

    module_name = "webhook"
    # enough events to reach the failure threshold
    targets = ["blacklanternsecurity.com", "evilcorp.com", "evilcorp.net", "evilcorp.org"]

    async def setup_after_prep(self, module_test):
        module_test.module._api_retry_backoff = 0.01
        self.requests = 0

        async def custom_callback(request):
            self.requests += 1
            return MockResponse(status_code=500)

        module_test.blasthttp_mock.add_callback(custom_callback)

    def check(self, module_test, events):
        assert self.requests == module_test.module.api_failure_abort_threshold
        assert module_test.module.errored is True


class TestWebhookSSLVerify(TestWebhook):
    """By default the webhook follows web.ssl_verify_infrastructure, like other API calls."""

    module_name = "webhook"
    expected_ssl_verify = True

    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)
        self.ssl_verify = []
        web = module_test.scan.helpers.web
        original_request = web.request

        async def recording_request(*args, **kwargs):
            self.ssl_verify.append(kwargs.get("ssl_verify"))
            return await original_request(*args, **kwargs)

        web.request = recording_request

    def check(self, module_test, events):
        super().check(module_test, events)
        assert self.ssl_verify and all(v is self.expected_ssl_verify for v in self.ssl_verify)


class TestWebhookSSLVerifyOverride(TestWebhookSSLVerify):
    """The module's ssl_verify option overrides the global setting."""

    config_overrides = {
        "modules": {"webhook": {**TestWebhook.config_overrides["modules"]["webhook"], "ssl_verify": False}}
    }
    expected_ssl_verify = False
