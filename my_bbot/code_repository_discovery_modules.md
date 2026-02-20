# Discovery modules for entry event `CODE_REPOSITORY` (BBOT)
This doc is entry-event based and lists modules that support `CODE_REPOSITORY` input and the events they emit.

## Entry event model
- Entry event: `CODE_REPOSITORY`
- Selection rule: modules that consume `CODE_REPOSITORY` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `CODE_REPOSITORY` modules (example):
  - `bbot -t example.com -m docker_pull ggshield git_clone gitdumper github_workflows`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m docker_pull ggshield git_clone gitdumper github_workflows -rf passive`

## Enable a specific set of `CODE_REPOSITORY` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m docker_pull ggshield git_clone gitdumper github_workflows`

## API keys
Put keys in your config (or pass via `-c`):
- Example (modules that still need keys): `bbot -t example.com -m docker_pull git_clone github_workflows postman_download -c modules.git_clone.api_key=YOURKEY modules.github_workflows.api_key=YOURKEY modules.postman_download.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `FILESYSTEM`: `docker_pull`, `git_clone`, `gitdumper`, `github_workflows`, `postman_download`.
- Emit `FINDING`: `ggshield`, `gitleaks`, `kingfisher`, `noseyparker`, `trufflehog`.
- Emit `MOBILE_APP`: `google_playstore`.
- Emit `VULNERABILITY`: `ggshield`, `gitleaks`, `kingfisher`, `noseyparker`, `trufflehog`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `code_repository-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./code_repository-discovery-yes.yml`

```yaml
description: CODE_REPOSITORY discovery with all modules marked "Should use = Yes"

modules:
  - docker_pull
  - ggshield
  - git_clone
  - gitdumper
  - github_workflows
  - gitleaks
  - google_playstore
  - kingfisher
  - noseyparker
  - postman_download
  - trufflehog

config:
  modules:
    git_clone:
      api_key: ${env:GIT_CLONE_API_KEY}
    github_workflows:
      api_key: ${env:GITHUB_WORKFLOWS_API_KEY}
    postman_download:
      api_key: ${env:POSTMAN_DOWNLOAD_API_KEY}
```

## Modules supporting entry event `CODE_REPOSITORY`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| docker_pull | FILESYSTEM | Module `docker_pull` functionality. | No | Yes, recommended | Yes |
| ggshield | FINDING | Module `ggshield` functionality. | No | Yes, recommended | Yes |
| ggshield | VULNERABILITY | Module `ggshield` functionality. | No | Yes, recommended | Yes |
| git_clone | FILESYSTEM | Module `git_clone` functionality. | Yes | Yes, recommended | Yes |
| gitdumper | FILESYSTEM | Module `gitdumper` functionality. | No | Yes, recommended | Yes |
| github_workflows | FILESYSTEM | Module `github_workflows` functionality. | Yes | Yes, recommended | Yes |
| gitleaks | FINDING | Module `gitleaks` functionality. | No | Yes, recommended | Yes |
| gitleaks | VULNERABILITY | Module `gitleaks` functionality. | No | Yes, recommended | Yes |
| google_playstore | MOBILE_APP | Module `google_playstore` functionality. | No | Yes, recommended | Yes |
| kingfisher | FINDING | Module `kingfisher` functionality. | No | Yes, recommended | Yes |
| kingfisher | VULNERABILITY | Module `kingfisher` functionality. | No | Yes, recommended | Yes |
| noseyparker | FINDING | Module `noseyparker` functionality. | No | Yes, recommended | Yes |
| noseyparker | VULNERABILITY | Module `noseyparker` functionality. | No | Yes, recommended | Yes |
| postman_download | FILESYSTEM | Module `postman_download` functionality. | Yes | Yes, recommended | Yes |
| trufflehog | FINDING | Module `trufflehog` functionality. | No | Yes, recommended | Yes |
| trufflehog | VULNERABILITY | Module `trufflehog` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
