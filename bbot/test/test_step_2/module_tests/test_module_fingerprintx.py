import json

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_HOSTPORT, HTTPSERVER_PORT


class TestFingerprintx(ModuleTestBase):
    targets = [HTTPSERVER_HOSTPORT]

    def check(self, module_test, events):
        assert any(
            event.type == "PROTOCOL"
            and event.host == module_test.scan.helpers.make_ip_type("127.0.0.1")
            and event.port == HTTPSERVER_PORT
            and event.data["protocol"] == "HTTP"
            for event in events
        ), "HTTP protocol not detected"


class TestFingerprintxURLs(ModuleTestBase):
    """Mocks fingerprintx output to verify URL_UNVERIFIED construction across IPv4/IPv6 and default/non-default ports."""

    module_name = "fingerprintx"
    targets = [
        "127.0.0.1:80",
        "127.0.0.1:8443",
        "[::1]:443",
        "[::1]:8080",
    ]
    config_overrides = {"modules": {"fingerprintx": {"skip_common_web": False}}}

    # (host, port, protocol) -> what fingerprintx pretends to find
    fake_results = [
        ("127.0.0.1", 80, "HTTP"),
        ("127.0.0.1", 8443, "HTTPS"),
        ("::1", 443, "HTTPS"),
        ("::1", 8080, "HTTP"),
    ]

    async def setup_after_prep(self, module_test):
        results = self.fake_results

        async def fake_run_process_live(self, command, **kwargs):
            for host, port, protocol in results:
                yield json.dumps({"ip": host, "host": host, "port": port, "protocol": protocol})

        module_test.monkeypatch.setattr(module_test.module.__class__, "run_process_live", fake_run_process_live)

    def check(self, module_test, events):
        urls = {e.data["url"] for e in events if e.type == "URL_UNVERIFIED"}
        expected = {
            "http://127.0.0.1/",
            "https://127.0.0.1:8443/",
            "https://[::1]/",
            "http://[::1]:8080/",
        }
        assert expected.issubset(urls), f"missing URLs; got {urls}"

        protocol_events = [e for e in events if e.type == "PROTOCOL"]
        assert any(
            e.host == module_test.scan.helpers.make_ip_type("::1") and e.port == 443 and e.data["protocol"] == "HTTPS"
            for e in protocol_events
        ), "IPv6 PROTOCOL event missing — parent lookup likely broken"
        assert any(
            e.host == module_test.scan.helpers.make_ip_type("127.0.0.1")
            and e.port == 8443
            and e.data["protocol"] == "HTTPS"
            for e in protocol_events
        ), "IPv4 PROTOCOL event missing"
