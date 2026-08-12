from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_SSL_HOSTPORT


class TestSSLCert(ModuleTestBase):
    targets = [HTTPSERVER_SSL_HOSTPORT, "bbottest.notreal"]
    config_overrides = {"scope": {"report_distance": 1}}

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.data == "www.bbottest.notreal" and str(e.module) == "sslcert" and e.scope_distance == 0
            ]
        ), "Failed to detect subject alternate name (SAN)"
        assert 1 == len(
            [e for e in events if e.data == "test.notreal" and str(e.module) == "sslcert" and e.scope_distance == 1]
        ), "Failed to detect main subject"
