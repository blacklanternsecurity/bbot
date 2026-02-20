# Discovery modules for entry event `URL_UNVERIFIED` (BBOT)
This doc is entry-event based and lists modules that support `URL_UNVERIFIED` input and the events they emit.

## Entry event model
- Entry event: `URL_UNVERIFIED`
- Selection rule: modules that consume `URL_UNVERIFIED` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `URL_UNVERIFIED` modules (example):
  - `bbot -t example.com -m code_repository filedownload httpx oauth portfilter retirejs`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m code_repository filedownload httpx oauth portfilter retirejs -rf passive`

## Enable a specific set of `URL_UNVERIFIED` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m code_repository filedownload httpx oauth portfilter retirejs`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m code_repository filedownload httpx oauth portfilter retirejs -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `(none)`: `portfilter`.
- Emit `CODE_REPOSITORY`: `code_repository`.
- Emit `DNS_NAME`: `oauth`.
- Emit `FILESYSTEM`: `filedownload`.
- Emit `FINDING`: `retirejs`.
- Emit `HTTP_RESPONSE`: `httpx`.
- Emit `SOCIAL`: `social`.
- Emit `URL`: `httpx`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `url_unverified-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./url_unverified-discovery-yes.yml`

```yaml
description: URL_UNVERIFIED discovery with all modules marked "Should use = Yes"

modules:
  - code_repository
  - filedownload
  - httpx
  - oauth
  - portfilter
  - retirejs
  - social
```

## Modules supporting entry event `URL_UNVERIFIED`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| code_repository | CODE_REPOSITORY | Module `code_repository` functionality. | No | Yes, recommended | Yes |
| filedownload | FILESYSTEM | Watch for common filetypes and download them. | No | Yes, recommended | Yes |
| httpx | HTTP_RESPONSE | Module `httpx` functionality. | No | Yes, recommended | Yes |
| httpx | URL | Module `httpx` functionality. | No | Yes, recommended | Yes |
| oauth | DNS_NAME | Module `oauth` functionality. | No | Yes, recommended | Yes |
| portfilter | (none) | Module `portfilter` functionality. | No | Yes, recommended | Yes |
| retirejs | FINDING | Module `retirejs` functionality. | No | Yes, recommended | Yes |
| social | SOCIAL | Module `social` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
