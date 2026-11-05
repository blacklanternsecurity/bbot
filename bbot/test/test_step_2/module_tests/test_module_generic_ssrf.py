import re
import asyncio
from werkzeug.wrappers import Response

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL
from bbot.modules.base import BaseModule


def extract_subdomain_tag(data):
    pattern = r"http://([a-z0-9]{4})\.fakedomain\.fakeinteractsh\.com"
    match = re.search(pattern, data)
    if match:
        return match.group(1)


class TestGeneric_SSRF(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "generic_ssrf"]
    config_overrides = {
        "interactsh_disable": False,
    }

    def request_handler(self, request):
        subdomain_tag = None

        if request.method == "GET":
            subdomain_tag = extract_subdomain_tag(request.full_path)
        elif request.method == "POST":
            subdomain_tag = extract_subdomain_tag(request.data.decode())
        if subdomain_tag:
            asyncio.run(
                self.interactsh_mock_instance.mock_interaction(
                    subdomain_tag, msg=f"{request.method}: {request.data.decode()}"
                )
            )

        return Response("alive", status=200)

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("generic_ssrf")

        # Mock at the helper creation level BEFORE modules are set up
        def mock_interactsh_factory(*args, **kwargs):
            return self.interactsh_mock_instance

        # Apply the mock to the core helpers so modules get the mock during setup
        from bbot.core.helpers.helper import ConfigAwareHelper

        module_test.monkeypatch.setattr(ConfigAwareHelper, "interactsh", mock_interactsh_factory)

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        total_findings = 0

        for e in events:
            if e.type == "FINDING":
                total_findings += 1

        assert total_findings == 60, "Incorrect number of findings detected"

        assert any(
            e.type == "FINDING"
            and "Out-of-band interaction: [Generic SSRF (GET)]"
            and "[Triggering Parameter: Dest]" in e.data["description"]
            for e in events
        ), "Failed to detect Generic SSRF (GET)"
        assert any(
            e.type == "FINDING" and "Out-of-band interaction: [Generic SSRF (POST)]" in e.data["description"]
            for e in events
        ), "Failed to detect Generic SSRF (POST)"
        assert any(
            e.type == "FINDING" and "Out-of-band interaction: [Generic XXE] [HTTP]" in e.data["description"]
            for e in events
        ), "Failed to detect Generic SSRF (XXE)"


class TestGeneric_SSRF_httponly(TestGeneric_SSRF):
    config_overrides = {"modules": {"generic_ssrf": {"skip_dns_interaction": True}}}

    def check(self, module_test, events):
        total_findings = 0

        for e in events:
            if e.type == "FINDING":
                total_findings += 1

        # With skip_dns_interaction=True, only HTTP-protocol findings are emitted (no DNS)
        assert total_findings == 30, "Incorrect number of findings detected"


class TestGeneric_SSRF_nowafpls_bypass(ModuleTestBase):
    """Generic_SSRF_POST should pad its body via nowafpls when the URL is WAF-tagged and the WAF is
    bypassable; the resulting SSRF (POST) FINDING should carry the ``used-nowafpls`` tag while GET/XXE
    findings emitted for the same host do not (their submodules don't use padding)."""

    targets = ["generic-ssrf-bypass.test"]
    modules_overrides = ["http", "generic_ssrf"]
    config_overrides = {"interactsh_disable": False}

    class DummyModule(BaseModule):
        watched_events = ["DNS_NAME"]
        _name = "dummy_module"

        async def handle_event(self, event):
            if event.data != "generic-ssrf-bypass.test":
                return
            url = self.scan.make_event(
                "http://generic-ssrf-bypass.test/",
                "URL",
                parent=event,
                tags=["waf", "cloudflare", "in-scope", "status-200"],
            )
            if url is not None:
                await self.emit_event(url)

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("generic_ssrf")

        def mock_factory(*a, **kw):
            return self.interactsh_mock_instance

        from bbot.core.helpers.helper import ConfigAwareHelper

        module_test.monkeypatch.setattr(ConfigAwareHelper, "interactsh", mock_factory)

    async def setup_after_prep(self, module_test):
        from blasthttp.mock import MockResponse

        await module_test.mock_dns({"generic-ssrf-bypass.test": {"A": ["127.0.0.1"]}})

        self.post_bodies: list[bytes] = []
        canary_re = re.compile(rb"http://([a-z0-9]{4})\.fakedomain\.fakeinteractsh\.com")
        interactsh_mock = self.interactsh_mock_instance

        def cb(request):
            method = request.method
            body = request.content or b""
            if isinstance(body, str):
                body = body.encode()

            if method == "GET":
                match = canary_re.search(request.url.query.encode() if hasattr(request.url, "query") else b"")
                if match:
                    interactsh_mock.mock_interaction(match.group(1).decode(), msg=f"GET: {request.url}")
                return MockResponse(status_code=200, text="alive")

            # POST branch
            self.post_bodies.append(body)
            has_pad = body.startswith(b"__nowafpls_pad=")
            has_malicious_script = b"%3Cscript" in body or b"<script" in body

            # nowafpls's own probe: baseline OK, unpadded malicious blocked (403), padded OK.
            if has_malicious_script and not has_pad:
                return MockResponse(status_code=403, text="Attention Required! | Cloudflare")

            match = canary_re.search(body)
            if match:
                interactsh_mock.mock_interaction(match.group(1).decode(), msg="POST: <padded>")
                return MockResponse(status_code=200, text="alive")

            return MockResponse(status_code=200, text="Welcome to the application")

        module_test.blasthttp_mock.add_callback(callback=cb)
        module_test.scan.modules["dummy_module"] = self.DummyModule(module_test.scan)

    def check(self, module_test, events):
        # Filter to Generic_SSRF_POST bodies (form-encoded canaries); exclude XXE XML bodies which
        # also contain the canary but are handled by the un-padded Generic_XXE submodule.
        ssrf_post_bodies = [
            b for b in self.post_bodies if b"fakedomain.fakeinteractsh" in b and not b.startswith(b"<")
        ]
        assert ssrf_post_bodies, f"Generic_SSRF_POST fired no probes. All bodies: {self.post_bodies}"
        assert all(b.startswith(b"__nowafpls_pad=") for b in ssrf_post_bodies), (
            f"Generic_SSRF_POST bodies should be padded via nowafpls. Unpadded: "
            f"{[b for b in ssrf_post_bodies if not b.startswith(b'__nowafpls_pad=')]}"
        )
        post_finding = next(
            (e for e in events if e.type == "FINDING" and "Generic SSRF (POST)" in e.data.get("description", "")),
            None,
        )
        assert post_finding is not None, "Generic SSRF (POST) FINDING not emitted"
        assert "used-nowafpls" in post_finding.tags, (
            f"Generic SSRF (POST) finding should be tagged 'used-nowafpls': {list(post_finding.tags)}"
        )
        # GET/XXE submodules don't use padding; their findings must NOT carry the tag.
        get_finding = next(
            (e for e in events if e.type == "FINDING" and "Generic SSRF (GET)" in e.data.get("description", "")),
            None,
        )
        if get_finding is not None:
            assert "used-nowafpls" not in get_finding.tags, (
                f"Generic SSRF (GET) finding must not carry 'used-nowafpls': {list(get_finding.tags)}"
            )
