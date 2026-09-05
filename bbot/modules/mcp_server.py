import json
import re

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

    When no spec-compliant server answers, the module falls back to fingerprinting
    REST-style MCP *tool backends* -- HTTP services that expose tools to agents but
    do not speak the JSON-RPC protocol, so the handshake never matches them. These
    are fingerprinted from a read-only identity path only; their command and tool
    routes are never requested.

    Passive/safe detection tier: complements the invasive Nuclei templates BBOT
    already runs opt-in (exposed-mcp-sse-server, CVE-2025-49596). This surfaces the
    exposure by protocol handshake in a default scan; nuclei confirms exploitability.
    """

    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["safe", "active", "web"]
    meta = {
        "description": "Detect exposed Model Context Protocol (MCP) servers and enumerate their tools",
        "created_date": "2026-09-04",
        "author": "@repins267",
    }

    # One probe per host:port: many URLs surface per host, but the MCP endpoint set is
    # host-wide, so re-probing per discovered path would only add noise.
    per_hostport_only = True

    class Config(BaseModuleConfig):
        mcp_endpoint_paths: list[str] = Field(
            ["/mcp", "/sse", "/messages", "/api/mcp", "/v1/mcp", "/mcp/sse"],
            description="Paths to probe for an MCP endpoint",
        )
        enumerate_tools: bool = Field(
            True,
            description="After a successful handshake, list the server's tools (read-only)",
        )
        detect_rest_backends: bool = Field(
            True,
            description="Also fingerprint REST-style MCP tool backends that don't speak the protocol",
        )
        detect_legacy_sse: bool = Field(
            True,
            description="Also detect the deprecated HTTP+SSE transport (GET /sse endpoint event)",
        )

    # Advertised during the handshake. Servers negotiate down if they speak an older
    # revision, so this does not need to match the target exactly.
    protocol_version = "2025-03-26"
    http_timeout = 10
    # Bounded read for the streaming SSE probe: we only need the first event, so we cap
    # both the time we wait and the bytes we read, then close. This is what keeps the
    # legacy-transport check from ever hanging a scan on an open SSE stream.
    sse_probe_timeout = 6
    sse_probe_maxbytes = 2048

    # REST-style MCP tool backends: HTTP services that expose tools/commands to AI agents
    # but do NOT speak the JSON-RPC protocol, so the handshake above never matches them.
    # Each is fingerprinted by GETting a read-only identity/health path and matching a
    # stable string in the body. Command and tool-invocation routes are never touched --
    # only the identity path is requested. Verified signatures only.
    #
    # name: (label, [identity paths], body pattern, severity, confidence, impact, cves)
    rest_backends = {
        "mcp-kali-server": (
            "MCP Kali tools server",
            ["/health"],
            r"Kali Linux Tools API Server",
            "CRITICAL",
            "CONFIRMED",
            "unauthenticated command execution via /api/command + offensive tooling -- RCE as a service",
            [],
        ),
    }

    async def setup(self):
        self.enumerate_tools = self.config.get("enumerate_tools", True)
        self.paths = self.config.get("mcp_endpoint_paths", [])
        self.detect_rest_backends = self.config.get("detect_rest_backends", True)
        self.detect_legacy_sse = self.config.get("detect_legacy_sse", True)
        self._rest_backends = {
            name: (label, paths, re.compile(pattern, re.I), severity, confidence, impact, cves)
            for name, (label, paths, pattern, severity, confidence, impact, cves) in self.rest_backends.items()
        }
        return True

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

        # No Streamable-HTTP server answered. Try the deprecated HTTP+SSE transport
        # (still common on 2025-era servers), then the REST tool-backend fallback.
        if self.detect_legacy_sse and await self._check_legacy_sse(base_url, event):
            return
        if self.detect_rest_backends:
            await self._check_rest_backends(base_url, event)

    async def _check_legacy_sse(self, base_url, event):
        """Detect the deprecated HTTP+SSE MCP transport.

        On that transport a GET to the SSE endpoint immediately emits an SSE
        ``event: endpoint`` whose data is the POST message path -- an MCP-specific
        handshake marker that a generic SSE endpoint does not send. We stream the
        response but read only the first event (bounded by time and bytes) and then
        close, so an always-open SSE stream can never hang the scan.
        """
        import httpx

        for path in ("/sse", "/mcp/sse"):
            url = f"{base_url}{path}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=self.sse_probe_timeout) as client:
                    async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as response:
                        if "text/event-stream" not in response.headers.get("content-type", "").lower():
                            continue
                        chunk = b""
                        async for piece in response.aiter_bytes():
                            chunk += piece
                            if b"event: endpoint" in chunk or len(chunk) >= self.sse_probe_maxbytes:
                                break
            except Exception as e:
                self.debug(f"Legacy SSE probe failed for {url}: {e}")
                continue

            body = chunk.decode("utf-8", errors="replace")
            # MCP-specific: an "endpoint" event pointing at the /messages POST path
            if "event: endpoint" not in body or "/messages" not in body:
                continue

            await self.emit_event(
                {"host": str(event.host), "technology": "mcp-server", "url": url},
                "TECHNOLOGY",
                event,
                context=f"{{module}} identified {{event.type}}: MCP server (legacy HTTP+SSE) at {url}",
            )
            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "name": "Exposed MCP server (legacy HTTP+SSE)",
                    "description": (
                        f"Exposed MCP server on the deprecated HTTP+SSE transport at {url} -- "
                        f"unauthenticated GET returned the MCP 'endpoint' handshake event. "
                        f"Detected via the SSE handshake event (bounded read)."
                    ),
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                },
                "FINDING",
                event,
                context=f"{{module}} found {{event.type}}: legacy HTTP+SSE MCP server at {url}",
            )
            return True
        return False

    async def _check_rest_backends(self, base_url, event):
        for name, (label, paths, pattern, severity, confidence, impact, cves) in self._rest_backends.items():
            for path in paths:
                url = f"{base_url}{path}"
                response = await self.helpers.request(url=url, method="GET", timeout=self.http_timeout)
                if response is None:
                    continue
                body = getattr(response, "text", "") or ""
                if not pattern.search(body):
                    continue
                await self.emit_event(
                    {"host": str(event.host), "technology": name, "url": url},
                    "TECHNOLOGY",
                    event,
                    context=f"{{module}} identified {{event.type}}: {label} at {url}",
                )
                data = {
                    "host": str(event.host),
                    "url": url,
                    "name": f"Exposed MCP tool backend: {label}",
                    "description": (
                        f"Exposed {label} REST tool backend at {url} ({impact}). "
                        f"Fingerprinted from its identity endpoint."
                    ),
                    "severity": severity,
                    "confidence": confidence,
                }
                if cves:
                    data["cves"] = cves
                await self.emit_event(
                    data,
                    "FINDING",
                    event,
                    context=f"{{module}} found {{event.type}}: exposed {label} at {url}",
                )
                return  # one backend per host is enough

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
            {"host": str(event.host), "technology": "mcp-server", "url": url},
            "TECHNOLOGY",
            event,
            context=f"{{module}} identified {{event.type}}: MCP server ({label}) at {url}",
        )

        # Reaching this point means the handshake completed with no credentials, from
        # outside the host -- three MCP-spec control failures at once: not localhost-bound,
        # no authentication, and (over http://) no transport security.
        issues = ["remote", "unauthenticated"]
        if url.lower().startswith("http://"):
            issues.append("no TLS")

        description = (
            f"Exposed MCP server ({label}, protocol {negotiated}) at {url} -- "
            f"initialize handshake completed {', '.join(issues)}."
        )
        if tools:
            shown = ", ".join(tools[:15])
            more = f" (+{len(tools) - 15} more)" if len(tools) > 15 else ""
            description += f" Tools ({len(tools)}): {shown}{more}."

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
