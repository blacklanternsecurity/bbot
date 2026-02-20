# Discovery modules for entry event `RAW_TEXT` (BBOT)
This doc is entry-event based and lists modules that support `RAW_TEXT` input and the events they emit.

## Entry event model
- Entry event: `RAW_TEXT`
- Selection rule: modules that consume `RAW_TEXT` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `RAW_TEXT` modules (example):
  - `bbot -t example.com -m trufflehog`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m trufflehog -rf passive`

## Enable a specific set of `RAW_TEXT` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m trufflehog`

## API keys
Put keys in your config (or pass via `-c`):
- None required for `trufflehog` tool mode.

## What these modules do
- Grouped by emitted event type:
- Emit `FINDING`: `trufflehog`.
- Emit `VULNERABILITY`: `trufflehog`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `raw_text-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./raw_text-discovery-yes.yml`

```yaml
description: RAW_TEXT discovery with all modules marked "Should use = Yes"

modules:
  - trufflehog

config:
  modules: {}
```

## Modules supporting entry event `RAW_TEXT`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| trufflehog | FINDING | Module `trufflehog` functionality. | No | Yes, recommended | Yes |
| trufflehog | VULNERABILITY | Module `trufflehog` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
