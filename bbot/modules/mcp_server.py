import json

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.base import BaseModule


class mcp_server(BaseModule):
    """Find Model Context Protocol (MCP) servers exposed on the web.

    MCP servers bridge AI agents to real tools and data. The specification is
    explicit that they SHOULD bind to localhost, SHOULD authenticate every
    connection, and MUST validate the Origin header. An MCP endpoint that
    completes an unauthenticated ``initialize`` handshake from the outside has
    failed all of those at once, and its tools can be enumerated -- and
    potentially invoked -- with whatever permissions the server was delegated.

    Detection is a real protocol handshake rather than a banner guess, so a hit
    is definitive. Only read-only methods are used: ``initialize`` and
    ``tools/list``. No tool is ever invoked.
    """

    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["safe", "active", "web"]
    meta = {
        "description": "Detect exposed Model Context Protocol (MCP) servers and enumerate their tools",
        "created_date": "2026-09-04",
        "author": "@repins267",
    }

    class Config(BaseModuleConfig):
        mcp_endpoint_paths: list[str] = Field(
            ["/mcp", "/sse", "/messages", "/api/mcp", "/v1/mcp", "/mcp/sse"],
            description="Paths to probe for an MCP endpoint",
        )
        enumerate_tools: bool = Field(
            True,
            description="After a successful handshake, list the server's tools (read-only)",
        )

    # Advertised during the handshake. Servers negotiate down if they speak an older
    # revision, so this does not need to match the target exactly.
    protocol_version = "2025-03-26"
    http_timeout = 10

    async def setup(self):
        self.enumerate_tools = self.config.get("enumerate_tools", True)
        self.paths = self.config.get("mcp_endpoint_paths", [])
        return True

    async def filter_event(self, event):
        # one probe per base URL, not per discovered path
        base_url = event.parsed_url._replace(path="/", query="", fragment="").geturl()
        return hash(base_url)

    def _rpc(self, method, params=None, msg_id=1, notification=False):
        payload = {"jsonrpc": "2.0", "method": method}
        if not notification:
            payload["id"] = msg_id
        if params is not None:
            payload["params"] = params
        return payload

    def _headers(self, session_id=None):
        headers = {
            "Content-Type": "application/json",
            # the spec requires clients to accept both response shapes
            "Accept": "application/json, text/event-stream",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return headers

    def _parse_rpc(self, response):
        """Return the JSON-RPC payload from a response body, JSON or SSE-wrapped."""
        if response is None:
            return None
        text = getattr(response, "text", "") or ""
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            # an SSE frame carries the JSON-RPC message on its "data:" line
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    try:
                        return json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        continue
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _is_initialize_result(payload):
        """A genuine InitializeResult, not just any JSON that happens to be served."""
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            return False
        result = payload.get("result")
        if not isinstance(result, dict):
            return False
        # protocolVersion is mandatory in InitializeResult; serverInfo is near-universal
        return "protocolVersion" in result or "serverInfo" in result

    async def handle_event(self, event):
        base_url = event.parsed_url._replace(path="/", query="", fragment="").geturl().rstrip("/")
        for path in self.paths:
            url = f"{base_url}{path}"
            response = await self.helpers.request(
                url=url,
                method="POST",
                headers=self._headers(),
                json=self._rpc(
                    "initialize",
                    {
                        "protocolVersion": self.protocol_version,
                        "capabilities": {},
                        "clientInfo": {"name": "bbot", "version": "1.0"},
                    },
                ),
                timeout=self.http_timeout,
            )
            if response is None:
                continue
            payload = self._parse_rpc(response)
            if not self._is_initialize_result(payload):
                continue

            result = payload["result"]
            server_info = result.get("serverInfo") or {}
            name = str(server_info.get("name") or "unknown")
            version = str(server_info.get("version") or "")
            negotiated = str(result.get("protocolVersion") or "unknown")
            session_id = response.headers.get("mcp-session-id")

            tools = []
            if self.enumerate_tools:
                tools = await self._list_tools(url, session_id)

            await self._report(event, url, name, version, negotiated, tools)
            # one MCP endpoint per host is enough
            return

    async def _list_tools(self, url, session_id):
        """Complete the lifecycle and read the tool list. Read-only; never invokes a tool."""
        try:
            # the spec requires this notification before normal operations
            await self.helpers.request(
                url=url,
                method="POST",
                headers=self._headers(session_id),
                json=self._rpc("notifications/initialized", notification=True),
                timeout=self.http_timeout,
            )
            response = await self.helpers.request(
                url=url,
                method="POST",
                headers=self._headers(session_id),
                json=self._rpc("tools/list", {}, msg_id=2),
                timeout=self.http_timeout,
            )
            payload = self._parse_rpc(response)
            if not isinstance(payload, dict):
                return []
            tools = payload.get("result", {}).get("tools", [])
            return [str(t.get("name")) for t in tools if isinstance(t, dict) and t.get("name")]
        except Exception as e:
            self.debug(f"Failed to enumerate tools at {url}: {e}")
            return []

    async def _report(self, event, url, name, version, negotiated, tools):
        label = f"{name} {version}".strip()
        await self.emit_event(
            {"host": str(event.host), "technology": f"mcp-server:{name}", "url": url},
            "TECHNOLOGY",
            event,
            context=f"{{module}} identified {{event.type}}: MCP server ({label}) at {url}",
        )

        # Reaching this point means the handshake completed with no credentials, from
        # outside the host. Per the MCP spec that is three control failures at once:
        # the server is not bound to localhost, it does not authenticate connections,
        # and (over http://) it carries no transport security.
        issues = ["reachable remotely", "no authentication required"]
        if url.lower().startswith("http://"):
            issues.append("no TLS")

        description = (
            f"Exposed Model Context Protocol server ({label}, protocol {negotiated}) at {url}. "
            f"The initialize handshake completed unauthenticated ({', '.join(issues)}). "
            f"MCP servers act on behalf of AI agents with delegated permissions, so an exposed "
            f"instance may allow an attacker to enumerate and invoke its tools."
        )
        if tools:
            shown = ", ".join(tools[:15])
            more = f" (+{len(tools) - 15} more)" if len(tools) > 15 else ""
            description += f" Exposed tools ({len(tools)}): {shown}{more}."

        await self.emit_event(
            {
                "host": str(event.host),
                "url": url,
                "name": "Exposed MCP server",
                "description": description,
                "severity": "HIGH",
                "confidence": "CONFIRMED",
            },
            "FINDING",
            event,
            context=f"{{module}} found {{event.type}}: unauthenticated MCP server at {url}",
        )
