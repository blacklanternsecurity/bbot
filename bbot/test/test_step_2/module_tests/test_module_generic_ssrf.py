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
    modules_overrides = ["httpx", "generic_ssrf"]

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
        module_test.monkeypatch.setattr(
            module_test.scan.helpers, "interactsh", lambda *args, **kwargs: self.interactsh_mock_instance
        )

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        total_vulnerabilities = 0
        total_findings = 0

        for e in events:
            if e.type == "VULNERABILITY":
                total_vulnerabilities += 1
            elif e.type == "FINDING":
                total_findings += 1

        assert total_vulnerabilities == 30, "Incorrect number of vulnerabilities detected"
        assert total_findings == 30, "Incorrect number of findings detected"

        assert any(
            e.type == "VULNERABILITY"
            and "Out-of-band interaction: [Generic SSRF (GET)]"
            and "[Triggering Parameter: Dest]" in e.data["description"]
            for e in events
        ), "Failed to detect Generic SSRF (GET)"
        assert any(
            e.type == "VULNERABILITY" and "Out-of-band interaction: [Generic SSRF (POST)]" in e.data["description"]
            for e in events
        ), "Failed to detect Generic SSRF (POST)"
        assert any(
            e.type == "VULNERABILITY" and "Out-of-band interaction: [Generic XXE] [HTTP]" in e.data["description"]
            for e in events
        ), "Failed to detect Generic SSRF (XXE)"


class TestGeneric_SSRF_httponly(TestGeneric_SSRF):
    config_overrides = {"modules": {"generic_ssrf": {"skip_dns_interaction": True}}}

    def check(self, module_test, events):
        total_vulnerabilities = 0
        total_findings = 0

        for e in events:
            if e.type == "VULNERABILITY":
                total_vulnerabilities += 1
            elif e.type == "FINDING":
                total_findings += 1

        assert total_vulnerabilities == 30, "Incorrect number of vulnerabilities detected"
        assert total_findings == 0, "Incorrect number of findings detected"
