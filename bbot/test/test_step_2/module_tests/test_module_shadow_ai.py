from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestShadowAI(ModuleTestBase):
    targets = [
        "api.openai.com",  # subdomain of a catalog entry -> TECHNOLOGY
        "all-hands.dev",  # exact catalog entry, high risk -> TECHNOLOGY
        "notopenai.com",  # lookalike, must NOT match
        "127.0.0.1:11434",  # Ollama default port -> FINDING
        "127.0.0.1:9999",  # unrelated port, must NOT match
    ]
    modules_overrides = ["shadow_ai"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "api.openai.com": {"A": ["127.0.0.1"]},
                "all-hands.dev": {"A": ["127.0.0.1"]},
                "notopenai.com": {"A": ["127.0.0.1"]},
            }
        )

    def check(self, module_test, events):
        technologies = [e for e in events if e.type == "TECHNOLOGY"]
        findings = [e for e in events if e.type == "FINDING"]

        # a subdomain of a catalog entry is attributed to its provider
        assert 1 == len(
            [e for e in technologies if e.data["technology"] == "ai:openai" and e.data["host"] == "api.openai.com"]
        ), "did not detect OpenAI usage via api.openai.com"

        # exact catalog entry (agent platform)
        assert 1 == len(
            [e for e in technologies if e.data["technology"] == "ai:openhands" and e.data["host"] == "all-hands.dev"]
        ), "did not detect OpenHands"

        # false-positive guard: a lookalike domain must never match
        assert not [e for e in technologies if "notopenai.com" in e.data["host"]], (
            "notopenai.com incorrectly matched openai.com"
        )

        # exposed self-hosted runtime on a distinctive port
        ollama = [e for e in findings if "Ollama" in e.data["name"]]
        assert 1 == len(ollama), "did not flag Ollama on port 11434"
        assert ollama[0].data["severity"] == "HIGH"
        assert ollama[0].data["confidence"] == "MEDIUM"
        assert "11434" in ollama[0].data["description"]

        # false-positive guard: unrelated ports produce nothing
        assert not [e for e in findings if "9999" in e.data.get("description", "")], (
            "unrelated port 9999 incorrectly flagged"
        )


class TestShadowAIAgentGateway(ModuleTestBase):
    """An exposed agent-gateway control interface is identified from the response body.

    Port matching alone would miss this: roughly half of exposed gateways sit behind
    80/443 rather than their documented port.
    """

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "shadow_ai"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"uri": "/"},
            respond_args={
                "response_data": ("<html><head><title>OpenClaw Control</title></head><body>gateway</body></html>")
            },
        )

    def check(self, module_test, events):
        gateways = [e for e in events if e.type == "FINDING" and "agent gateway" in e.data["name"]]
        assert 1 == len(gateways), "did not detect the exposed agent gateway"
        finding = gateways[0]
        assert finding.data["severity"] == "HIGH"
        assert finding.data["confidence"] == "CONFIRMED"
        assert "CVE-2026-25253" in finding.data["cves"]
        # the module must not claim to have verified the CVE
        assert "does not test for it" in finding.data["description"]

        assert [e for e in events if e.type == "TECHNOLOGY" and "openclaw" in e.data["technology"]], (
            "should have emitted a TECHNOLOGY event for the gateway"
        )


class TestShadowAIAgentGatewayNegative(TestShadowAIAgentGateway):
    """An ordinary web page must not be mistaken for an agent gateway."""

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"uri": "/"},
            respond_args={"response_data": "<html><head><title>Acme Corp</title></head><body>hi</body></html>"},
        )

    def check(self, module_test, events):
        assert not [e for e in events if e.type == "FINDING"], "ordinary page should not be flagged"


class TestShadowAIFiltering(TestShadowAI):
    """min_risk and categories narrow the results."""

    config_overrides = {"modules": {"shadow_ai": {"min_risk": "high", "check_ports": False}}}

    def check(self, module_test, events):
        technologies = [e for e in events if e.type == "TECHNOLOGY"]
        findings = [e for e in events if e.type == "FINDING"]

        # high-risk agent platform still reported
        assert 1 == len([e for e in technologies if e.data["technology"] == "ai:openhands"]), (
            "high-risk entry should survive min_risk=high"
        )
        # medium-risk assistant filtered out
        assert not [e for e in technologies if e.data["technology"] == "ai:openai"], (
            "medium-risk entry should be filtered by min_risk=high"
        )
        # port checking disabled
        assert not findings, "check_ports=False should suppress FINDINGs"
