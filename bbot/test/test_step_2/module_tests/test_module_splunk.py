import json
import httpx

from .base import ModuleTestBase


class TestSplunk(ModuleTestBase):
    downstream_url = "https://splunk.blacklanternsecurity.fakedomain:1234/services/collector"
    config_overrides = {
        "modules": {
            "splunk": {
                "url": downstream_url,
                "hectoken": "HECTOKEN",
                "index": "bbot_index",
                "source": "bbot_source",
            }
        }
    }

    def verify_data(self, j):
        if not j["source"] == "bbot_source":
            return False
        if not j["index"] == "bbot_index":
            return False
        data = j["event"]
        if not data["data"] == "blacklanternsecurity.com" and data["type"] == "DNS_NAME":
            return False
        return True

    async def setup_after_prep(self, module_test):
        self.url_correct = False
        self.method_correct = False
        self.got_event = False
        self.headers_correct = False

        async def custom_callback(request):
            j = json.loads(request.content)
            if request.url == self.downstream_url:
                self.url_correct = True
            if request.method == "POST":
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
        module_test.httpx_mock.add_response()

    def check(self, module_test, events):
        assert self.got_event == True
        assert self.headers_correct == True
        assert self.method_correct == True
        assert self.url_correct == True
