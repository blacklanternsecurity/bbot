from ..bbot_fixtures import *  # noqa: F401
from ..modules_test_classes import HttpxMockHelper


class Scope_test_blacklist(HttpxMockHelper):
    additional_modules = ["httpx"]

    blacklist = ["127.0.0.1"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "URL":
                return False
        return True


class Scope_test_whitelist(HttpxMockHelper):
    additional_modules = ["httpx"]

    whitelist = ["255.255.255.255"]

    def mock_args(self):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        self.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check_events(self, events):
        for e in events:
            if e.type == "URL":
                return False
        return True


def test_scope_blacklist(bbot_config, bbot_scanner, bbot_httpserver):
    x = Scope_test_blacklist(bbot_config, bbot_scanner, bbot_httpserver, module_name="httpx")
    x.run()


def test_scope_whitelist(bbot_config, bbot_scanner, bbot_httpserver):
    x = Scope_test_whitelist(bbot_config, bbot_scanner, bbot_httpserver, module_name="httpx")
    x.run()
