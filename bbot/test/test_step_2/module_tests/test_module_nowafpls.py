from blasthttp.mock import MockResponse

from .base import ModuleTestBase
from bbot.modules.base import BaseModule


class TestNowafpls(ModuleTestBase):
    targets = ["nowafpls.test"]
    modules_overrides = ["nowafpls"]
    config_overrides = {"modules": {"nowafpls": {"padding_size": 1024}}}

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        _name = "dummy_module"

        async def handle_event(self, event):
            if event.data != "nowafpls.test":
                return
            url_event = self.scan.make_event(
                "http://nowafpls.test/",
                "URL",
                parent=event,
                tags=["cloudflare", "in-scope", "status-200"],
            )
            if url_event is not None:
                await self.emit_event(url_event)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"nowafpls.test": {"A": ["127.0.0.1"]}})

        module_test.scan.modules["dummy_module"] = self.DummyModule(module_test.scan)

        def waf_callback(request):
            content = request.content or b""
            if isinstance(content, str):
                content = content.encode()
            if content.startswith(b"padding="):
                return MockResponse(status_code=200, text="Welcome to the application")
            return MockResponse(
                status_code=403,
                text="Attention Required! | Cloudflare\nCloudflare Ray ID: 1234abcd",
            )

        module_test.blasthttp_mock.add_callback(callback=waf_callback, url="http://nowafpls.test/")

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert findings, "No FINDING event produced"
        assert any(
            e.data.get("name") == "WAF Bypass via Body Padding"
            and e.data.get("severity") == "LOW"
            and e.data.get("confidence") == "CONFIRMED"
            and "nowafpls-style body padding" in e.data.get("description", "")
            for e in findings
        ), f"Expected nowafpls FINDING not present: {[e.data for e in findings]}"
