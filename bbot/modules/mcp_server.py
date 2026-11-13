import csv
import json
import re
from typing import Union

from bbot import __version__
from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.base import BaseModule


class mcp_server(BaseModule):
    """Find exposed Model Context Protocol (MCP) servers by completing the initialize handshake."""

    watched_events = ["URL"]
    produced_events = ["FINDING", "TECHNOLOGY"]
    flags = ["safe", "active", "web"]
    meta = {
        "description": "Detect exposed Model Context Protocol (MCP) servers and enumerate their tools",
        "created_date": "2026-09-04",
        "author": "@repins267",
    }

    per_hostport_only = True

    class Config(BaseModuleConfig):
        mcp_endpoint_paths: Union[str, list[str]] = Field(
            ["/mcp", "/sse", "/messages", "/api/mcp", "/v1/mcp", "/mcp/sse"],
            description="Paths to probe for an MCP endpoint. Accepts a list, or a wordlist file path / URL (one path per line)",
        )
        signatures: Union[str, list[str]] = Field(
            "",
            description="REST tool-backend signature file path or URL (CSV, see docs/modules/mcp_server.md). Empty = bundled default. Accepts a list of paths/URLs to merge",
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
            description="Also detect the deprecated HTTP+SSE transport (GET endpoint event)",
        )

    protocol_version = "2025-03-26"
    default_signatures = "mcp_server_signatures.txt"
    sse_probe_max_bytes = 64
    max_tools_listed = 15
    signature_columns = ("name", "label", "path", "body_regex", "severity", "confidence", "impact", "cves")

    async def setup_deps(self):
        paths = self.config.get("mcp_endpoint_paths")
        self.paths_file = await self.helpers.wordlist(paths) if isinstance(paths, str) else None
        signatures = self.config.get("signatures") or f"{self.helpers.wordlist_dir}/{self.default_signatures}"
        self.signatures_file = await self.helpers.wordlist(signatures)
        return True

    async def setup(self):
        if self.paths_file is None:
            self.paths = list(self.config.get("mcp_endpoint_paths"))
        else:
            self.paths = [line.strip() for line in self.helpers.read_file(self.paths_file) if self._is_row(line)]
        self.enumerate_tools = self.config.get("enumerate_tools")
        self.detect_rest_backends = self.config.get("detect_rest_backends")
        self.detect_legacy_sse = self.config.get("detect_legacy_sse")
        self.signatures = self._load_signatures(self.signatures_file)
        return True

    @staticmethod
    def _is_row(line):
        line = line.strip()
        return bool(line) and not line.startswith("#")

    def _load_signatures(self, filename):
        rows = [line for line in self.helpers.read_file(filename) if self._is_row(line)]
        signatures = []
        for fields in csv.reader(rows):
            if len(fields) != len(self.signature_columns):
                self.warning(
                    f"Skipping signature row with {len(fields)} columns (expected {len(self.signature_columns)}): {fields}"
                )
                continue
            sig = dict(zip(self.signature_columns, (f.strip() for f in fields)))
            try:
                sig["body_regex"] = re.compile(sig["body_regex"], re.I)
            except re.error as e:
                self.warning(f"Skipping signature {sig['name']}: invalid regex ({e})")
                continue
            sig["severity"] = sig["severity"].upper()
            sig["confidence"] = sig["confidence"].upper()
            sig["cves"] = [c.strip() for c in sig["cves"].split(";") if c.strip()]
            signatures.append(sig)
        if rows and not signatures:
            self.warning(f"No valid signatures loaded from {filename}")
        return signatures

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
            "Accept": "application/json, text/event-stream",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return headers

    def _parse_rpc(self, response):
        if response is None:
            return None
        text = getattr(response, "text", "") or ""
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    try:
                        return json.loads(line.removeprefix("data:").strip())
                    except json.JSONDecodeError:
                        continue
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _is_initialize_result(payload):
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            return False
        result = payload.get("result")
        if not isinstance(result, dict):
            return False
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
                        "clientInfo": {"name": "bbot", "version": str(__version__)},
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
            return

        if self.detect_legacy_sse and await self._check_legacy_sse(base_url, event):
            return
        if self.detect_rest_backends:
            await self._check_rest_backends(base_url, event)

    async def _check_legacy_sse(self, base_url, event):
        for path in self.paths:
            url = f"{base_url}{path}"
            response = await self.helpers.request(
                url=url,
                method="GET",
                headers={"Accept": "text/event-stream"},
                max_body_size=self.sse_probe_max_bytes,
                timeout=self.http_timeout,
            )
            if response is None:
                continue
            if "text/event-stream" not in response.headers.get("content-type", "").lower():
                continue
            body = getattr(response, "text", "") or ""
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
        for sig in self.signatures:
            url = f"{base_url}{sig['path']}"
            response = await self.helpers.request(url=url, method="GET", timeout=self.http_timeout)
            if response is None:
                continue
            body = getattr(response, "text", "") or ""
            if not sig["body_regex"].search(body):
                continue
            label = sig["label"]
            await self.emit_event(
                {"host": str(event.host), "technology": sig["name"], "url": url},
                "TECHNOLOGY",
                event,
                context=f"{{module}} identified {{event.type}}: {label} at {url}",
            )
            data = {
                "host": str(event.host),
                "url": url,
                "name": f"Exposed MCP tool backend: {label}",
                "description": f"Exposed {label} REST tool backend at {url} ({sig['impact']}). Fingerprinted from its identity endpoint.",
                "severity": sig["severity"],
                "confidence": sig["confidence"],
            }
            if sig["cves"]:
                data["cves"] = sig["cves"]
            await self.emit_event(
                data,
                "FINDING",
                event,
                context=f"{{module}} found {{event.type}}: exposed {label} at {url}",
            )
            return

    async def _list_tools(self, url, session_id):
        try:
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

        issues = ["remote", "unauthenticated"]
        if url.lower().startswith("http://"):
            issues.append("no TLS")

        description = (
            f"Exposed MCP server ({label}, protocol {negotiated}) at {url} -- "
            f"initialize handshake completed {', '.join(issues)}."
        )
        if tools:
            shown = ", ".join(tools[: self.max_tools_listed])
            hidden = len(tools) - self.max_tools_listed
            more = f" (+{hidden} more)" if hidden > 0 else ""
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
