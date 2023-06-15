from .base import ModuleTestBase


class TestSSLCert(ModuleTestBase):
    targets = ["127.0.0.1:9999", "bbottest.notreal"]

    def check(self, module_test, events):
        assert any(
            e.data == "www.bbottest.notreal" and str(e.module) == "sslcert" for e in events
        ), "Failed to detect subdomain"
