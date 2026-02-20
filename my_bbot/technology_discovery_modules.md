# Discovery modules for entry event `TECHNOLOGY` (BBOT)
This doc is entry-event based and lists modules that support `TECHNOLOGY` input and the events they emit.

## Entry event model
- Entry event: `TECHNOLOGY`
- Selection rule: modules that consume `TECHNOLOGY` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `TECHNOLOGY` modules (example):
  - `bbot -t example.com -m wpscan`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m wpscan -rf passive`

## Enable a specific set of `TECHNOLOGY` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m wpscan`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m wpscan -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `CODE_REPOSITORY`: `gitlab_onprem`.
- Emit `FINDING`: `gitlab_onprem`, `wpscan`.
- Emit `SOCIAL`: `gitlab_onprem`.
- Emit `TECHNOLOGY`: `gitlab_onprem`, `wpscan`.
- Emit `URL_UNVERIFIED`: `wpscan`.
- Emit `VULNERABILITY`: `wpscan`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `technology-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./technology-discovery-yes.yml`

```yaml
description: TECHNOLOGY discovery with all modules marked "Should use = Yes"

modules:
  - wpscan

config:
  modules:
    wpscan:
      api_key: ${env:WPSCAN_API_KEY}
```

## Modules supporting entry event `TECHNOLOGY`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| gitlab_onprem | CODE_REPOSITORY | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | FINDING | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | SOCIAL | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | TECHNOLOGY | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| wpscan | FINDING | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |
| wpscan | TECHNOLOGY | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |
| wpscan | URL_UNVERIFIED | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |
| wpscan | VULNERABILITY | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
