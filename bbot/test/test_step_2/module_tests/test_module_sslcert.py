from .base import ModuleTestBase


class TestSSLCert(ModuleTestBase):
    targets = ["8.8.8.8:443"]

    def check(self, module_test, events):
        assert any(e.data == "dns.google" and str(e.module) == "sslcert" for e in events), "Failed to detect subdomain"
