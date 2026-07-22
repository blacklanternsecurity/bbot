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
                tags=["waf", "cloudflare", "in-scope", "status-200"],
            )
            if url_event is not None:
                await self.emit_event(url_event)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"nowafpls.test": {"A": ["127.0.0.1"]}})

        module_test.scan.modules["dummy_module"] = self.DummyModule(module_test.scan)

        # Response model for the mocked host:
        #   * benign body ("q=hello")                          -> baseline app response
        #   * unpadded malicious ("q=<script>...")             -> WAF block page (403)
        #   * padded malicious ("__nowafpls_pad=AAA...&q=...") -> baseline app response (bypass works)
        def waf_callback(request):
            content = request.content or b""
            if isinstance(content, str):
                content = content.encode()
            if content.startswith(b"__nowafpls_pad="):
                return MockResponse(status_code=200, text="Welcome to the application")
            if b"%3Cscript" in content or b"<script" in content:
                return MockResponse(
                    status_code=403,
                    text="Attention Required! | Cloudflare\nCloudflare Ray ID: 1234abcd",
                )
            return MockResponse(status_code=200, text="Welcome to the application")

        # No url= constraint: HttpCompare's baseline sample #2 appends random query
        # params to the URL, so we accept any URL for this test host.
        module_test.blasthttp_mock.add_callback(callback=waf_callback)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert findings, "No FINDING event produced"
        assert any(
            e.data.get("name") == "WAF Bypass via Body Padding"
            and e.data.get("severity") == "LOW"
            and e.data.get("confidence") == "CONFIRMED"
            and "nowafpls-style body padding" in e.data.get("description", "")
            # padding size is reported in the description so operators know what
            # size worked without having to correlate against the run config
            and "padding size: 1024 bytes" in e.data.get("description", "")
            for e in findings
        ), f"Expected nowafpls FINDING not present: {[e.data for e in findings]}"


class TestNowafplsSkipsRedirects(ModuleTestBase):
    """Redirect (3xx) URLs get skipped so that per_host_only doesn't burn the
    module's one-per-host slot on the http->https redirect before the real
    https URL arrives."""

    targets = ["nowafpls-redir.test"]
    modules_overrides = ["nowafpls"]

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        _name = "dummy_module"

        async def handle_event(self, event):
            if event.data != "nowafpls-redir.test":
                return
            # emit a 3xx URL first (would be the http->https redirect in reality)
            url_event = self.scan.make_event(
                "http://nowafpls-redir.test/",
                "URL",
                parent=event,
                tags=["waf", "cloudflare", "in-scope", "status-301"],
            )
            if url_event is not None:
                await self.emit_event(url_event)

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"nowafpls-redir.test": {"A": ["127.0.0.1"]}})
        module_test.scan.modules["dummy_module"] = self.DummyModule(module_test.scan)

        # if the module tries to probe the redirect URL, this callback would be exercised;
        # asserting no FINDING covers the "was filtered out before probing" invariant
        def waf_callback(request):
            return MockResponse(status_code=200, text="should not be reached")

        module_test.blasthttp_mock.add_callback(callback=waf_callback)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and str(e.module) == "nowafpls"]
        assert not findings, f"nowafpls should not fire on 3xx URLs, but produced: {[e.data for e in findings]}"
