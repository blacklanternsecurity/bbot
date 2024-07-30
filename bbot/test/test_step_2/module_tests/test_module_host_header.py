import re
from werkzeug.wrappers import Response

from .base import ModuleTestBase


def extract_subdomain_tag(data):
    pattern = r"([a-z0-9]{4})\.fakedomain\.fakeinteractsh\.com"
    match = re.search(pattern, data)
    if match:
        return match.group(1)


class TestHost_Header(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "host_header"]

    fake_host = "fakedomain.fakeinteractsh.com"

    def request_handler(self, request):
        subdomain_tag = None
        subdomain_tag = extract_subdomain_tag(request.headers["Host"])

        # Standard (with reflection)
        if subdomain_tag:
            self.interactsh_mock_instance.mock_interaction(subdomain_tag)
            return Response(f"Alive, host is: {subdomain_tag}.{self.fake_host}", status=200)

        # Host Header Overrides
        subdomain_tag_overrides = extract_subdomain_tag(request.headers["X-Forwarded-For"])
        if subdomain_tag_overrides:
            return Response(f"Alive, host is: {subdomain_tag}.{self.fake_host}", status=200)

        return Response(f"Alive, host is: defaulthost.com", status=200)

    async def setup_before_prep(self, module_test):
        self.interactsh_mock_instance = module_test.mock_interactsh("host_header")
        module_test.monkeypatch.setattr(
            module_test.scan.helpers, "interactsh", lambda *args, **kwargs: self.interactsh_mock_instance
        )

    async def setup_after_prep(self, module_test):
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        # We can't fully test all the use-cases because werkzeug abstracts away some of our RFC-violating tricks :/

        for e in events:
            assert any(
                e.type == "FINDING"
                and "Possible Host header injection. Injection technique: standard" in e.data["description"]
                for e in events
            ), "Failed to detect Possible Host Header Injection (standard)"
            assert any(
                e.type == "FINDING"
                and "Possible Host header injection. Injection technique: host override headers"
                in e.data["description"]
                for e in events
            ), "Failed to detect Possible Host Header Injection (host override headers)"
            assert any(
                e.type == "FINDING" and "Spoofed Host header (standard) [HTTP] interaction" in e.data["description"]
                for e in events
            ), "Failed to detect Spoofed Host header (standard) [HTTP] interaction"
