# Discovery modules for entry event `URL_HINT` (BBOT)
This doc is entry-event based and lists modules that support `URL_HINT` input and the events they emit.

## Entry event model
- Entry event: `URL_HINT`
- Selection rule: modules that consume `URL_HINT` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `URL_HINT` modules (example):
  - `bbot -t example.com -m ffuf_shortnames`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m ffuf_shortnames -rf passive`

## Enable a specific set of `URL_HINT` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m ffuf_shortnames`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m ffuf_shortnames -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `URL_UNVERIFIED`: `ffuf_shortnames`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `url_hint-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./url_hint-discovery-yes.yml`

```yaml
description: URL_HINT discovery with all modules marked "Should use = Yes"

modules:
  - ffuf_shortnames
```

## Modules supporting entry event `URL_HINT`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| ffuf_shortnames | URL_UNVERIFIED | Module `ffuf_shortnames` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
