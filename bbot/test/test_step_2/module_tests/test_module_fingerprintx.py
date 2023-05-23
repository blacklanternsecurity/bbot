from .base import ModuleTestBase


class TestFingerprintx(ModuleTestBase):
    targets = ["127.0.0.1:8888"]

    def check(self, module_test, events):
        assert any(
            event.type == "PROTOCOL"
            and event.host == module_test.scan.helpers.make_ip_type("127.0.0.1")
            and event.port == 8888
            and event.data["protocol"] == "HTTP"
            for event in events
        ), "HTTP protocol not detected"
