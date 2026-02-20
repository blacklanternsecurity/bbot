# Discovery modules for entry event `WEB_PARAMETER` (BBOT)
This doc is entry-event based and lists modules that support `WEB_PARAMETER` input and the events they emit.

## Entry event model
- Entry event: `WEB_PARAMETER`
- Selection rule: modules that consume `WEB_PARAMETER` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `WEB_PARAMETER` modules (example):
  - `bbot -t example.com -m hunt paramminer_cookies paramminer_getparams paramminer_headers reflected_parameters`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m hunt paramminer_cookies paramminer_getparams paramminer_headers reflected_parameters -rf passive`

## Enable a specific set of `WEB_PARAMETER` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m hunt paramminer_cookies paramminer_getparams paramminer_headers reflected_parameters`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m hunt paramminer_cookies paramminer_getparams paramminer_headers reflected_parameters -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `FINDING`: `hunt`, `paramminer_cookies`, `paramminer_getparams`, `reflected_parameters`.
- Emit `WEB_PARAMETER`: `paramminer_headers`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `web_parameter-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./web_parameter-discovery-yes.yml`

```yaml
description: WEB_PARAMETER discovery with all modules marked "Should use = Yes"

modules:
  - hunt
  - paramminer_cookies
  - paramminer_getparams
  - paramminer_headers
  - reflected_parameters
```

## Modules supporting entry event `WEB_PARAMETER`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| hunt | FINDING | Module `hunt` functionality. | No | Yes, recommended | Yes |
| paramminer_cookies | FINDING | Inspired by https://github.com/PortSwigger/param-miner | No | Yes, recommended | Yes |
| paramminer_getparams | FINDING | Inspired by https://github.com/PortSwigger/param-miner | No | Yes, recommended | Yes |
| paramminer_headers | WEB_PARAMETER | Inspired by https://github.com/PortSwigger/param-miner | No | Yes, recommended | Yes |
| reflected_parameters | FINDING | Module `reflected_parameters` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
