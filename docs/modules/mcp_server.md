# MCP Server Detection (mcp_server)

## Overview

`mcp_server` finds [Model Context Protocol](https://modelcontextprotocol.io/) servers that are reachable from outside. MCP servers connect AI agents to tools and data; the specification says they should bind to localhost and authenticate every connection. One that answers an unauthenticated `initialize` handshake from the internet has done neither, and whatever tools it advertises are available to anyone who can reach it.

The module is `active` and `safe`: it completes the read-only part of the protocol lifecycle (`initialize`, `notifications/initialized`, `tools/list`) and never calls a tool. It runs on every `URL` BBOT discovers, once per host:port.

Three detection paths, tried in order:

| Path | Signal | Result |
|---|---|---|
| **Streamable HTTP** (current transport) | `POST` of a JSON-RPC `initialize` to each configured endpoint path returns a real `InitializeResult` (JSON or SSE-framed) | `FINDING` (HIGH / CONFIRMED) naming the server, protocol version and advertised tools, plus a `mcp-server` `TECHNOLOGY` |
| **Legacy HTTP+SSE** (deprecated transport) | `GET` with `Accept: text/event-stream` returns an SSE stream whose first frame is the MCP `endpoint` event | `FINDING` (HIGH / CONFIRMED) plus `mcp-server` `TECHNOLOGY` |
| **REST tool backends** | An HTTP service that exposes tools to agents without speaking JSON-RPC, matched by a signature file (identity path + body regex) | `FINDING` with the severity/confidence from the signature row, plus a `TECHNOLOGY` named after the signature |

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
[FINDING]     Severity: [HIGH] Confidence: [CONFIRMED] Exposed MCP server (demo-server 1.0.0, protocol 2025-03-26)
              at http://10.0.0.5:8000/mcp -- initialize handshake completed remote, unauthenticated, no TLS.
              Tools (2): read_file, execute_command.
```

A server on the deprecated HTTP+SSE transport (for example the Damn Vulnerable MCP Server lab):

```
[TECHNOLOGY]  mcp-server (http://10.0.0.5:9001/sse)
[FINDING]     Severity: [HIGH] Confidence: [CONFIRMED] Exposed MCP server on the deprecated HTTP+SSE transport
              at http://10.0.0.5:9001/sse -- unauthenticated GET returned the MCP 'endpoint' handshake event.
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
    # REST tool-backend signatures. Empty = the bundled bbot/wordlists/mcp_server_signatures.txt.
    # Accepts a file path or URL, or a list of them (merged, duplicates removed).
    signatures: ""
    enumerate_tools: true
    detect_rest_backends: true
    detect_legacy_sse: true
```

| Option | Type | Default | Description |
|---|---|---|---|
| `mcp_endpoint_paths` | list, or string | six common paths | Endpoint paths to probe. A string is treated as a wordlist file path or URL, one path per line |
| `signatures` | string or list | `""` (bundled file) | REST tool-backend signature file path(s) or URL(s), CSV format below. Multiple files are merged with deduplication |
| `enumerate_tools` | bool | `true` | After a successful handshake, call `tools/list` and include the tool names in the finding |
| `detect_rest_backends` | bool | `true` | Try the signature file when no MCP endpoint answers |
| `detect_legacy_sse` | bool | `true` | Try the deprecated HTTP+SSE transport when no Streamable HTTP endpoint answers |

All requests go through BBOT's HTTP helpers, so the scan's proxy, user agent, rate limit, SSL policy and `http_timeout` apply.

### Signature file format

One CSV row per REST tool backend. Lines starting with `#` and blank lines are ignored; quote a field if it contains a comma.

```
# name,label,path,body_regex,severity,confidence,impact,cves
my-agent-gateway,My Agent Gateway,/api/status,"Agent Gateway v[0-9.]+ ready",HIGH,CONFIRMED,exposes tool execution to unauthenticated clients,CVE-2026-00001;CVE-2026-00002
```

| Column | Meaning |
|---|---|
| `name` | Short slug; becomes the `TECHNOLOGY` value |
| `label` | Display name used in the finding |
| `path` | Identity/health path that is requested with `GET` |
| `body_regex` | Case-insensitive regex matched against that response body |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` |
| `confidence` | `CONFIRMED`, `HIGH`, `MEDIUM` or `LOW` |
| `impact` | One clause describing what the exposure gives an attacker; appears in the finding |
| `cves` | Semicolon-separated CVE IDs, may be empty |

Rows with the wrong number of columns or an invalid regex are skipped with a warning; the rest of the file still loads.

To add your own backends without editing installed files, merge the bundled signatures with yours (duplicates are removed):

```yaml
modules:
  mcp_server:
    signatures:
      - /usr/lib/python3/site-packages/bbot/wordlists/mcp_server_signatures.txt
      - /path/to/my_signatures.txt
```

## Relationship to other modules

- `nuclei` ships templates for some of the same products (for example `exposed-mcp-sse-server`), but runs only when explicitly enabled because it is `invasive`. `mcp_server` is the `safe` tier that runs in a default scan and tells you where to point nuclei.
- `portscan` and `fingerprintx` report open ports and generic protocols; neither speaks MCP.
- Secrets that an MCP server might leak through its tool descriptions are out of scope here; `trufflehog` owns secret detection.
