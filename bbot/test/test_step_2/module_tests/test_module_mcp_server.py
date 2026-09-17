import json
import re

from werkzeug.wrappers import Response

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL

INITIALIZE_RESULT = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-03-26",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "test-mcp", "version": "1.2.3"},
    },
}
TOOLS_RESULT = {
    "jsonrpc": "2.0",
    "id": 2,
    "result": {"tools": [{"name": "read_file"}, {"name": "execute_command"}]},
}


class TestMCPServer(ModuleTestBase):
    """A JSON-speaking MCP endpoint is detected and its tools enumerated."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["mcp_server"]

    def request_handler(self, request):
        if not request.path.startswith("/mcp"):
            return Response("not found", status=404)
        body = json.loads(request.data or b"{}")
        method = body.get("method")
        if method == "initialize":
            return Response(
                json.dumps(INITIALIZE_RESULT),
                status=200,
                content_type="application/json",
                headers={"Mcp-Session-Id": "test-session-id"},
            )
        if method == "tools/list":
            return Response(json.dumps(TOOLS_RESULT), status=200, content_type="application/json")
        # notifications/initialized
        return Response("", status=202)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/"), request_handler=self.request_handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        technologies = [e for e in events if e.type == "TECHNOLOGY"]

        assert 1 == len(findings), "should have raised exactly one FINDING"
        finding = findings[0]
        assert finding.data["severity"] == "HIGH"
        assert finding.data["confidence"] == "CONFIRMED"
        assert finding.data["url"] == f"{HTTPSERVER_URL}/mcp"
        description = finding.data["description"]
        assert "test-mcp 1.2.3" in description
        assert "unauthenticated" in description
        assert "no TLS" in description, "plaintext http:// endpoint should be called out"
        # tools were enumerated
        assert "execute_command" in description
        assert "read_file" in description
        assert "Tools (2)" in description

        assert 1 == len([e for e in technologies if e.data["technology"] == "mcp-server"]), (
            "should have emitted an mcp-server TECHNOLOGY"
        )


class TestMCPServerSSE(TestMCPServer):
    """The same handshake, framed as Server-Sent Events, is parsed correctly."""

    def request_handler(self, request):
        if not request.path.startswith("/mcp"):
            return Response("not found", status=404)
        body = json.loads(request.data or b"{}")
        method = body.get("method")
        if method == "initialize":
            return Response(
                f"event: message\ndata: {json.dumps(INITIALIZE_RESULT)}\n\n",
                status=200,
                content_type="text/event-stream",
                headers={"Mcp-Session-Id": "test-session-id"},
            )
        if method == "tools/list":
            return Response(
                f"event: message\ndata: {json.dumps(TOOLS_RESULT)}\n\n",
                status=200,
                content_type="text/event-stream",
            )
        return Response("", status=202)


class TestMCPServerNoTools(TestMCPServer):
    """Tool enumeration disabled: the server is still reported, without a tool list."""

    config_overrides = {"modules": {"mcp_server": {"enumerate_tools": False}}}

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert 1 == len(findings)
        description = findings[0].data["description"]
        assert "test-mcp 1.2.3" in description
        assert "Tools (" not in description, "tools should not be enumerated when disabled"


class TestMCPServerRESTBackend(ModuleTestBase):
    """A REST tool backend (no MCP protocol) is fingerprinted from its identity endpoint."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["mcp_server"]

    def request_handler(self, request):
        # never speaks the JSON-RPC protocol; only the /health identity endpoint responds
        if request.path == "/health":
            return Response(
                json.dumps({"status": "healthy", "message": "Kali Linux Tools API Server is running"}),
                status=200,
                content_type="application/json",
            )
        return Response("not found", status=404)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/"), request_handler=self.request_handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert 1 == len(findings), "should have fingerprinted the REST tool backend"
        finding = findings[0]
        assert "MCP tool backend" in finding.data["name"]
        assert finding.data["severity"] == "CRITICAL"
        assert finding.data["confidence"] == "CONFIRMED"
        assert "/api/command" in finding.data["description"]
        # detection method is stated (identity endpoint), and the command route is named as attack surface
        assert "identity endpoint" in finding.data["description"]
        assert [e for e in events if e.type == "TECHNOLOGY" and e.data["technology"] == "mcp-kali-server"]


class TestMCPServerRESTBackendDisabled(TestMCPServerRESTBackend):
    """detect_rest_backends=false suppresses the REST fingerprint entirely."""

    config_overrides = {"modules": {"mcp_server": {"detect_rest_backends": False}}}

    def check(self, module_test, events):
        assert not [e for e in events if e.type == "FINDING"], "REST backend detection should be disabled"


class TestMCPServerLegacySSE(ModuleTestBase):
    """The deprecated HTTP+SSE transport: GET /sse emits an MCP 'endpoint' event."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["mcp_server"]

    def request_handler(self, request):
        if request.path == "/sse":
            # legacy MCP handshake: an SSE stream whose first event is the message endpoint
            return Response(
                "event: endpoint\ndata: /messages/?session_id=abc123\n\n",
                status=200,
                content_type="text/event-stream",
            )
        return Response("not found", status=404)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/"), request_handler=self.request_handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and "legacy HTTP+SSE" in e.data["name"]]
        assert 1 == len(findings), "did not detect the legacy HTTP+SSE MCP server"
        assert findings[0].data["severity"] == "HIGH"
        assert findings[0].data["confidence"] == "CONFIRMED"
        assert "bounded read" in findings[0].data["description"]
        assert [e for e in events if e.type == "TECHNOLOGY" and e.data["technology"] == "mcp-server"]


class TestMCPServerNegative(ModuleTestBase):
    """An ordinary JSON web app must not be mistaken for an MCP server."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["mcp_server"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": re.compile("/")},
            # valid JSON, and even valid JSON-RPC shape, but no InitializeResult
            respond_args={"response_data": json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"status": "ok"}})},
        )

    def check(self, module_test, events):
        assert all(e.type != "FINDING" for e in events), "non-MCP JSON endpoint should not be flagged"
        assert all(e.type != "TECHNOLOGY" for e in events), "non-MCP JSON endpoint should not be flagged"
