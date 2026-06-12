import re
import asyncio
from werkzeug.wrappers import Response

from .base import ModuleTestBase


def extract_subdomain_tag(data):
    pattern = r"http://([a-z0-9]{4})\.fakedomain\.fakeinteractsh\.com"
    match = re.search(pattern, data)
    if match:
        return match.group(1)


class TestGeneric_SSRF(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
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
