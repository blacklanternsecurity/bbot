# Discovery modules for entry event `HTTP_RESPONSE` (BBOT)
This doc is entry-event based and lists modules that support `HTTP_RESPONSE` input and the events they emit.

## Entry event model
- Entry event: `HTTP_RESPONSE`
- Selection rule: modules that consume `HTTP_RESPONSE` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `HTTP_RESPONSE` modules (example):
  - `bbot -t example.com -m ajaxpro badsecrets dotnetnuke filedownload host_header`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m ajaxpro badsecrets dotnetnuke filedownload host_header -rf passive`

## Enable a specific set of `HTTP_RESPONSE` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m ajaxpro badsecrets dotnetnuke filedownload host_header`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m ajaxpro badsecrets dotnetnuke filedownload host_header -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `CODE_REPOSITORY`: `gitlab_onprem`.
- Emit `DNS_NAME`: `ntlm`.
- Emit `FILESYSTEM`: `filedownload`.
- Emit `SOCIAL`: `gitlab_onprem`.
- Emit `TECHNOLOGY`: `badsecrets`, `dotnetnuke`, `gitlab_onprem`, `wpscan`.
- Emit `URL_UNVERIFIED`: `wpscan`.
- Emit `VULNERABILITY`: `ajaxpro`, `badsecrets`, `dotnetnuke`, `telerik`, `trufflehog`, `wpscan`.
- Emit `FINDING`: `ajaxpro`, `badsecrets`, `gitlab_onprem`, `host_header`, `newsletters`, `ntlm`, `paramminer_cookies`, `paramminer_getparams`, `telerik`, `trufflehog`, `wpscan`.
- Emit `WEB_PARAMETER`: `paramminer_headers`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `http_response-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./http_response-discovery-yes.yml`

```yaml
description: HTTP_RESPONSE discovery with all modules marked "Should use = Yes"

modules:
  - ajaxpro
  - badsecrets
  - dotnetnuke
  - filedownload
  - host_header
  - newsletters
  - ntlm
  - paramminer_cookies
  - paramminer_getparams
  - paramminer_headers
  - telerik
  - trufflehog
  - wpscan

config:
  modules:
    wpscan:
      api_key: ${env:WPSCAN_API_KEY}
```

## Modules supporting entry event `HTTP_RESPONSE`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| ajaxpro | FINDING | Reference: https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/ | No | Yes, recommended | Yes |
| ajaxpro | VULNERABILITY | Reference: https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/ | No | Yes, recommended | Yes |
| badsecrets | FINDING | Module `badsecrets` functionality. | No | Yes, recommended | Yes |
| badsecrets | TECHNOLOGY | Module `badsecrets` functionality. | No | Yes, recommended | Yes |
| badsecrets | VULNERABILITY | Module `badsecrets` functionality. | No | Yes, recommended | Yes |
| dotnetnuke | TECHNOLOGY | Module `dotnetnuke` functionality. | No | Yes, recommended | Yes |
| dotnetnuke | VULNERABILITY | Module `dotnetnuke` functionality. | No | Yes, recommended | Yes |
| filedownload | FILESYSTEM | Watch for common filetypes and download them. | No | Yes, recommended | Yes |
| gitlab_onprem | CODE_REPOSITORY | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | FINDING | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | SOCIAL | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| gitlab_onprem | TECHNOLOGY | Module `gitlab_onprem` functionality. | Yes | No, disabled by policy | No |
| host_header | FINDING | Module `host_header` functionality. | No | Yes, recommended | Yes |
| newsletters | FINDING | Module `newsletters` functionality. | No | Yes, recommended | Yes |
| ntlm | DNS_NAME | Todo: | No | Yes, recommended | Yes |
| ntlm | FINDING | Todo: | No | Yes, recommended | Yes |
| paramminer_cookies | FINDING | Inspired by https://github.com/PortSwigger/param-miner | No | Yes, recommended | Yes |
| paramminer_getparams | FINDING | Inspired by https://github.com/PortSwigger/param-miner | No | Yes, recommended | Yes |
| paramminer_headers | WEB_PARAMETER | Inspired by https://github.com/PortSwigger/param-miner | No | Yes, recommended | Yes |
| telerik | FINDING | Test for endpoints associated with Telerik.Web.UI.dll | No | Yes, recommended | Yes |
| telerik | VULNERABILITY | Test for endpoints associated with Telerik.Web.UI.dll | No | Yes, recommended | Yes |
| trufflehog | FINDING | Module `trufflehog` functionality. | No | Yes, recommended | Yes |
| trufflehog | VULNERABILITY | Module `trufflehog` functionality. | No | Yes, recommended | Yes |
| wpscan | FINDING | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |
| wpscan | TECHNOLOGY | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |
| wpscan | URL_UNVERIFIED | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |
| wpscan | VULNERABILITY | Module `wpscan` functionality. | Yes | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
