# Discovery modules for entry event `ORG_STUB` (BBOT)
This doc is entry-event based and lists modules that support `ORG_STUB` input and the events they emit.

## Entry event model
- Entry event: `ORG_STUB`
- Selection rule: modules that consume `ORG_STUB` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `ORG_STUB` modules (example):
  - `bbot -t example.com -m dockerhub github_org google_playstore postman`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m dockerhub github_org google_playstore postman -rf passive`

## Enable a specific set of `ORG_STUB` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m dockerhub github_org google_playstore postman`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m dockerhub github_org google_playstore postman -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `CODE_REPOSITORY`: `dockerhub`, `github_org`, `postman`.
- Emit `MOBILE_APP`: `google_playstore`.
- Emit `SOCIAL`: `dockerhub`.
- Emit `URL_UNVERIFIED`: `dockerhub`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `org_stub-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./org_stub-discovery-yes.yml`

```yaml
description: ORG_STUB discovery with all modules marked "Should use = Yes"

modules:
  - dockerhub
  - github_org
  - google_playstore
  - postman

config:
  modules:
    github_org:
      api_key: ${env:GITHUB_ORG_API_KEY}
    postman:
      api_key: ${env:POSTMAN_API_KEY}
```

## Modules supporting entry event `ORG_STUB`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| dockerhub | CODE_REPOSITORY | Module `dockerhub` functionality. | No | Yes, recommended | Yes |
| dockerhub | SOCIAL | Module `dockerhub` functionality. | No | Yes, recommended | Yes |
| dockerhub | URL_UNVERIFIED | Module `dockerhub` functionality. | No | Yes, recommended | Yes |
| github_org | CODE_REPOSITORY | Module `github_org` functionality. | Yes | Yes, recommended | Yes |
| google_playstore | MOBILE_APP | Module `google_playstore` functionality. | No | Yes, recommended | Yes |
| postman | CODE_REPOSITORY | Module `postman` functionality. | Yes | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
