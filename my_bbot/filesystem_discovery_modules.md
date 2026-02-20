# Discovery modules for entry event `FILESYSTEM` (BBOT)
This doc is entry-event based and lists modules that support `FILESYSTEM` input and the events they emit.

## Entry event model
- Entry event: `FILESYSTEM`
- Selection rule: modules that consume `FILESYSTEM` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `FILESYSTEM` modules (example):
  - `bbot -t example.com -m extractous ggshield gitleaks jadx kingfisher`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m extractous ggshield gitleaks jadx kingfisher -rf passive`

## Enable a specific set of `FILESYSTEM` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m extractous ggshield gitleaks jadx kingfisher`

## API keys
Put keys in your config (or pass via `-c`):
- None required for the recommended tool set (`extractous`, `ggshield`, `gitleaks`, `jadx`, `kingfisher`, `noseyparker`, `trufflehog`).

## What these modules do
- Grouped by emitted event type:
- Emit `FILESYSTEM`: `jadx`.
- Emit `FINDING`: `ggshield`, `gitleaks`, `kingfisher`, `noseyparker`, `trufflehog`.
- Emit `RAW_TEXT`: `extractous`.
- Emit `VULNERABILITY`: `ggshield`, `gitleaks`, `kingfisher`, `noseyparker`, `trufflehog`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `filesystem-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./filesystem-discovery-yes.yml`

```yaml
description: FILESYSTEM discovery with all modules marked "Should use = Yes"

modules:
  - extractous
  - ggshield
  - gitleaks
  - jadx
  - kingfisher
  - noseyparker
  - trufflehog

config:
  modules: {}
```

## Modules supporting entry event `FILESYSTEM`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| extractous | RAW_TEXT | Module `extractous` functionality. | No | Yes, recommended | Yes |
| ggshield | FINDING | Module `ggshield` functionality. | No | Yes, recommended | Yes |
| ggshield | VULNERABILITY | Module `ggshield` functionality. | No | Yes, recommended | Yes |
| gitleaks | FINDING | Module `gitleaks` functionality. | No | Yes, recommended | Yes |
| gitleaks | VULNERABILITY | Module `gitleaks` functionality. | No | Yes, recommended | Yes |
| jadx | FILESYSTEM | Module `jadx` functionality. | No | Yes, recommended | Yes |
| kingfisher | FINDING | Module `kingfisher` functionality. | No | Yes, recommended | Yes |
| kingfisher | VULNERABILITY | Module `kingfisher` functionality. | No | Yes, recommended | Yes |
| noseyparker | FINDING | Module `noseyparker` functionality. | No | Yes, recommended | Yes |
| noseyparker | VULNERABILITY | Module `noseyparker` functionality. | No | Yes, recommended | Yes |
| trufflehog | FINDING | Module `trufflehog` functionality. | No | Yes, recommended | Yes |
| trufflehog | VULNERABILITY | Module `trufflehog` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
