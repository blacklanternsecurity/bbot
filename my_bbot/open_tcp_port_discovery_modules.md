# Discovery modules for entry event `OPEN_TCP_PORT` (BBOT)
This doc is entry-event based and lists modules that support `OPEN_TCP_PORT` input and the events they emit.

## Entry event model
- Entry event: `OPEN_TCP_PORT`
- Selection rule: modules that consume `OPEN_TCP_PORT` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `OPEN_TCP_PORT` modules (example):
  - `bbot -t example.com -m fingerprintx httpx portfilter sslcert`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m fingerprintx httpx portfilter sslcert -rf passive`

## Enable a specific set of `OPEN_TCP_PORT` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m fingerprintx httpx portfilter sslcert`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m fingerprintx httpx portfilter sslcert -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `(none)`: `portfilter`.
- Emit `DNS_NAME`: `sslcert`.
- Emit `EMAIL_ADDRESS`: `sslcert`.
- Emit `HTTP_RESPONSE`: `httpx`.
- Emit `PROTOCOL`: `fingerprintx`.
- Emit `URL`: `httpx`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `open_tcp_port-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./open_tcp_port-discovery-yes.yml`

```yaml
description: OPEN_TCP_PORT discovery with all modules marked "Should use = Yes"

modules:
  - fingerprintx
  - httpx
  - portfilter
  - sslcert
```

## Modules supporting entry event `OPEN_TCP_PORT`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| fingerprintx | PROTOCOL | Module `fingerprintx` functionality. | No | Yes, recommended | Yes |
| httpx | HTTP_RESPONSE | Module `httpx` functionality. | No | Yes, recommended | Yes |
| httpx | URL | Module `httpx` functionality. | No | Yes, recommended | Yes |
| portfilter | (none) | Module `portfilter` functionality. | No | Yes, recommended | Yes |
| sslcert | DNS_NAME | Module `sslcert` functionality. | No | Yes, recommended | Yes |
| sslcert | EMAIL_ADDRESS | Module `sslcert` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
