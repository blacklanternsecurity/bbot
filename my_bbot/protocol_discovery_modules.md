# Discovery modules for entry event `PROTOCOL` (BBOT)
This doc is entry-event based and lists modules that support `PROTOCOL` input and the events they emit.

## Entry event model
- Entry event: `PROTOCOL`
- Selection rule: modules that consume `PROTOCOL` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `PROTOCOL` modules (example):
  - `bbot -t example.com -m medusa`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m medusa -rf passive`

## Enable a specific set of `PROTOCOL` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m medusa`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m medusa -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `VULNERABILITY`: `medusa`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `protocol-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./protocol-discovery-yes.yml`

```yaml
description: PROTOCOL discovery with all modules marked "Should use = Yes"

modules: []
```

## Modules supporting entry event `PROTOCOL`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| medusa | VULNERABILITY | Module `medusa` functionality. | No | Yes | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
