# Discovery modules for entry event `IP_RANGE` (BBOT)
This doc is entry-event based and lists modules that support `IP_RANGE` input and the events they emit.

## Entry event model
- Entry event: `IP_RANGE`
- Selection rule: modules that consume `IP_RANGE` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `IP_RANGE` modules (example):
  - `bbot -t example.com -m naabu portscan`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m naabu portscan -rf passive`

## Enable a specific set of `IP_RANGE` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m naabu portscan`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m naabu portscan -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `OPEN_TCP_PORT`: `naabu`, `portscan`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `ip_range-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./ip_range-discovery-yes.yml`

```yaml
description: IP_RANGE discovery with all modules marked "Should use = Yes"

modules: []
```

## Modules supporting entry event `IP_RANGE`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| naabu | OPEN_TCP_PORT | Module `naabu` functionality. | No | Yes | Yes |
| portscan | OPEN_TCP_PORT | Module `portscan` functionality. | No | Optional, active port scan | Optional |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
