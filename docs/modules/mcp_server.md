# MCP Server Detection (mcp_server)

## Overview

`mcp_server` finds [Model Context Protocol](https://modelcontextprotocol.io/) servers that are reachable from where the scan runs. MCP servers connect AI agents to tools and data. The specification allows remote servers and makes authorization optional, and some servers are public on purpose, so a completed handshake shows that a server is reachable, not that anything is wrong. Findings are `INFO`; the advertised tool list is what tells you whether the exposure matters.

The module is `active` and `safe`: it completes the read-only part of the protocol lifecycle (`initialize`, `notifications/initialized`, `tools/list`) and never calls a tool. It runs on every `URL` BBOT discovers, once per host:port.

Two detection paths, tried in order:

| Path | Signal | Result |
|---|---|---|
| **Streamable HTTP** (current transport) | `POST` of a JSON-RPC `initialize` to each configured endpoint path returns a real `InitializeResult` (JSON or SSE-framed) | `FINDING` (INFO / CONFIRMED) naming the server, protocol version and advertised tools, plus a `mcp-server` `TECHNOLOGY` |
| **Legacy HTTP+SSE** (deprecated transport) | `GET` with `Accept: text/event-stream` returns an SSE stream whose first frame is the MCP `endpoint` event | `FINDING` (INFO / CONFIRMED) plus `mcp-server` `TECHNOLOGY` |

The SSE probe reads only the first few bytes of the stream, a fixed cap smaller than one SSE frame, so an always-open stream returns immediately instead of waiting out the scan's HTTP timeout.

## Quick Start

```bash
# Scan a host for exposed MCP servers
bbot -t mcp.example.com -m mcp_server

# Include it in a normal web scan; it will probe every URL BBOT finds
bbot -t example.com -p subdomain-enum web-basic -m mcp_server

# Probe a known endpoint directly and skip tool enumeration
bbot -t http://10.0.0.5:8000 -m mcp_server -c modules.mcp_server.enumerate_tools=false
```

## Example Output

A server built on the official MCP Python SDK:

```
[TECHNOLOGY]  mcp-server (http://10.0.0.5:8000/mcp)
[FINDING]     Severity: [INFO] Confidence: [CONFIRMED] MCP server (demo-server 1.0.0, protocol 2025-03-26)
              at http://10.0.0.5:8000/mcp -- initialize handshake completed without credentials, over plaintext HTTP.
              Tools (2): read_file, execute_command.
```

A server on the deprecated HTTP+SSE transport (for example the Damn Vulnerable MCP Server lab):

```
[TECHNOLOGY]  mcp-server (http://10.0.0.5:9001/sse)
[FINDING]     Severity: [INFO] Confidence: [CONFIRMED] MCP server on the deprecated HTTP+SSE transport
              at http://10.0.0.5:9001/sse -- a GET returned the MCP 'endpoint' handshake event.
```

## Configuration

```yaml
modules:
  mcp_server:
    # Paths tried on every host:port. Either a YAML list, or a wordlist file path / URL with one path per line.
    mcp_endpoint_paths:
      - /mcp
      - /sse
      - /messages
      - /api/mcp
      - /v1/mcp
      - /mcp/sse
    enumerate_tools: true
    detect_legacy_sse: true
```

| Option | Type | Default | Description |
|---|---|---|---|
| `mcp_endpoint_paths` | list, or string | six common paths | Endpoint paths to probe. A string is treated as a wordlist file path or URL, one path per line |
| `enumerate_tools` | bool | `true` | After a successful handshake, call `tools/list` and include the tool names in the finding |
| `detect_legacy_sse` | bool | `true` | Try the deprecated HTTP+SSE transport when no Streamable HTTP endpoint answers |

All requests go through BBOT's HTTP helpers, so the scan's proxy, user agent, rate limit, SSL policy and `http_timeout` apply.

## Relationship to other modules

- `nuclei` ships templates for some of the same products (for example `exposed-mcp-sse-server`), but runs only when explicitly enabled because it is `invasive`. `mcp_server` is the `safe` tier that runs in a default scan and tells you where to point nuclei.
- `portscan` and `fingerprintx` report open ports and generic protocols; neither speaks MCP.
- Secrets that an MCP server might leak through its tool descriptions are out of scope here; `trufflehog` owns secret detection.
