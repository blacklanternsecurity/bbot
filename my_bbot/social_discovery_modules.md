# Discovery modules for entry event `SOCIAL` (BBOT)
This doc is entry-event based and lists modules that support `SOCIAL` input and the events they emit.

## Entry event model
- Entry event: `SOCIAL`
- Selection rule: modules that consume `SOCIAL` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `SOCIAL` modules (example):
  - `bbot -t example.com -m dockerhub github_org gitlab_com gowitness postman`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m dockerhub github_org gitlab_com gowitness postman -rf passive`

## Enable a specific set of `SOCIAL` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m dockerhub github_org gitlab_com gowitness postman`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m dockerhub github_org gitlab_com gowitness postman -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `CODE_REPOSITORY`: `dockerhub`, `github_org`, `gitlab_com`, `gitlab_onprem`, `postman`.
- Emit `FINDING`: `gitlab_onprem`.
- Emit `SOCIAL`: `dockerhub`, `gitlab_onprem`.
- Emit `TECHNOLOGY`: `gitlab_onprem`, `gowitness`.
- Emit `URL`: `gowitness`.
- Emit `URL_UNVERIFIED`: `dockerhub`, `gowitness`.
- Emit `WEBSCREENSHOT`: `gowitness`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `social-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./social-discovery-yes.yml`

```yaml
description: SOCIAL discovery with all modules marked "Should use = Yes"

modules:
  - dockerhub
  - github_org
  - gitlab_com
  - gowitness
  - postman

config:
  modules:
    github_org:
      api_key: ${env:GITHUB_ORG_API_KEY}
    gitlab_com:
      api_key: ${env:GITLAB_COM_API_KEY}
    postman:
      api_key: ${env:POSTMAN_API_KEY}
```

## Modules supporting entry event `SOCIAL`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| dockerhub | CODE_REPOSITORY | Module `dockerhub` functionality. | No | Yes, recommended | Yes |
| dockerhub | SOCIAL | Module `dockerhub` functionality. | No | Yes, recommended | Yes |
| dockerhub | URL_UNVERIFIED | Module `dockerhub` functionality. | No | Yes, recommended | Yes |
| github_org | CODE_REPOSITORY | Module `github_org` functionality. | Yes | Yes, recommended | Yes |
| gitlab_com | CODE_REPOSITORY | Module `gitlab_com` functionality. | Yes | Yes, recommended | Yes |
| gitlab_onprem | CODE_REPOSITORY | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | FINDING | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | SOCIAL | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | TECHNOLOGY | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gowitness | TECHNOLOGY | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| gowitness | URL | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| gowitness | URL_UNVERIFIED | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| gowitness | WEBSCREENSHOT | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| postman | CODE_REPOSITORY | Module `postman` functionality. | Yes | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
