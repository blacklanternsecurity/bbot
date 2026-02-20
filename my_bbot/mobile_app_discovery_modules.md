# Discovery modules for entry event `MOBILE_APP` (BBOT)
This doc is entry-event based and lists modules that support `MOBILE_APP` input and the events they emit.

## Entry event model
- Entry event: `MOBILE_APP`
- Selection rule: modules that consume `MOBILE_APP` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `MOBILE_APP` modules (example):
  - `bbot -t example.com -m apkpure`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m apkpure -rf passive`

## Enable a specific set of `MOBILE_APP` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m apkpure`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m apkpure -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `FILESYSTEM`: `apkpure`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `mobile_app-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./mobile_app-discovery-yes.yml`

```yaml
description: MOBILE_APP discovery with all modules marked "Should use = Yes"

modules:
  - apkpure
```

## Modules supporting entry event `MOBILE_APP`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| apkpure | FILESYSTEM | Module `apkpure` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
