import json
import re

from bbot import __version__
from .base import ModuleTestBase, tempwordlist
from bbot.test.worker import HTTPSERVER_URL

# The exact JSON-RPC bodies the module sends. pytest-httpserver matches a request's JSON body
# by equality, so each step of the handshake gets its own static expectation.
INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "id": 1,
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "bbot", "version": str(__version__)},
    },
}
INITIALIZED_NOTIFICATION = {"jsonrpc": "2.0", "method": "notifications/initialized"}
TOOLS_LIST_REQUEST = {"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}}

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


def json_body(payload):
    return json.dumps(payload)


def sse_body(payload):
    return f"event: message\ndata: {json.dumps(payload)}\n\n"


class TestMCPServer(ModuleTestBase):
    """A JSON-speaking MCP endpoint is detected and its tools enumerated."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["mcp_server"]
    content_type = "application/json"
    frame = staticmethod(json_body)

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/mcp", "json": INITIALIZE_REQUEST},
            respond_args={
                "response_data": self.frame(INITIALIZE_RESULT),
                "content_type": self.content_type,
                "headers": {"Mcp-Session-Id": "test-session-id"},
            },
        )
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/mcp", "json": INITIALIZED_NOTIFICATION},
            respond_args={"response_data": "", "status": 202},
        )
        module_test.set_expect_requests(
            expect_args={"method": "POST", "uri": "/mcp", "json": TOOLS_LIST_REQUEST},
            respond_args={"response_data": self.frame(TOOLS_RESULT), "content_type": self.content_type},
        )

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        technologies = [e for e in events if e.type == "TECHNOLOGY"]

        assert 1 == len(findings), "should have raised exactly one FINDING"
        finding = findings[0]
        assert finding.data["severity"] == "INFO"
        assert finding.data["confidence"] == "CONFIRMED"
        assert finding.data["url"] == f"{HTTPSERVER_URL}/mcp"
        description = finding.data["description"]
        assert "test-mcp 1.2.3" in description
        assert "without credentials" in description
        assert "plaintext HTTP" in description, "plaintext http:// endpoint should be called out"
        # tools were enumerated
        assert "execute_command" in description
        assert "read_file" in description
        assert "Tools (2)" in description

        assert 1 == len([e for e in technologies if e.data["technology"] == "mcp-server"]), (
            "should have emitted an mcp-server TECHNOLOGY"
        )


class TestMCPServerSSE(TestMCPServer):
    """The same handshake, framed as Server-Sent Events, is parsed correctly."""

    content_type = "text/event-stream"
    frame = staticmethod(sse_body)


class TestMCPServerNoTools(TestMCPServer):
    """Tool enumeration disabled: the server is still reported, without a tool list."""

    config_overrides = {"modules": {"mcp_server": {"enumerate_tools": False}}}

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert 1 == len(findings)
        description = findings[0].data["description"]
        assert "test-mcp 1.2.3" in description
        assert "Tools (" not in description, "tools should not be enumerated when disabled"


class TestMCPServerLegacySSE(ModuleTestBase):
    """The deprecated HTTP+SSE transport: GET /sse emits an MCP 'endpoint' event."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["mcp_server"]

    async def setup_after_prep(self, module_test):
        # legacy MCP handshake: an SSE stream whose first event is the message endpoint
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/sse"},
            respond_args={
                "response_data": "event: endpoint\ndata: /messages/?session_id=abc123\n\n",
                "content_type": "text/event-stream",
            },
        )

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and "legacy HTTP+SSE" in e.data["name"]]
        assert 1 == len(findings), "did not detect the legacy HTTP+SSE MCP server"
        assert findings[0].data["severity"] == "INFO"
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


class TestMCPServerPathsFromFile(TestMCPServer):
    """mcp_endpoint_paths given as a wordlist file instead of a literal list."""

    paths_file = tempwordlist(["# one endpoint path per line", "", "/nothing-here", "/mcp"])
    config_overrides = {"modules": {"mcp_server": {"mcp_endpoint_paths": str(paths_file)}}}

    def check(self, module_test, events):
        module = module_test.scan.modules["mcp_server"]
        assert module.paths == ["/nothing-here", "/mcp"], "comments and blank lines are dropped, order is kept"
        super().check(module_test, events)
