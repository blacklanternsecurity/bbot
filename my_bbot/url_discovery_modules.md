# Discovery modules for entry event `URL` (BBOT)
This doc is entry-event based and lists modules that support `URL` input and the events they emit.

## Entry event model
- Entry event: `URL`
- Selection rule: modules that consume `URL` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `URL` modules (example):
  - `bbot -t example.com -m ajaxpro aspnet_bin_exposure baddns_direct bypass403 ffuf generic_ssrf`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m ajaxpro aspnet_bin_exposure baddns_direct bypass403 ffuf generic_ssrf -rf passive`

## Enable a specific set of `URL` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m ajaxpro aspnet_bin_exposure baddns_direct bypass403 ffuf generic_ssrf`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m ajaxpro aspnet_bin_exposure baddns_direct bypass403 ffuf generic_ssrf -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `(none)`: `portfilter`.
- Emit `CODE_REPOSITORY`: `git`.
- Emit `DNS_NAME`: `ntlm`, `vhost`.
- Emit `FINDING`: `ajaxpro`, `baddns_direct`, `bypass403`, `git`, `graphql_introspection`, `ntlm`, `nuclei`, `smuggler`, `telerik`, `url_manipulation`.
- Emit `HTTP_RESPONSE`: `httpx`.
- Emit `TECHNOLOGY`: `gowitness`, `nuclei`.
- Emit `URL`: `gowitness`, `httpx`.
- Emit `URL_HINT`: `iis_shortnames`.
- Emit `URL_UNVERIFIED`: `ffuf`, `gowitness`, `robots`.
- Emit `VHOST`: `vhost`.
- Emit `VULNERABILITY`: `ajaxpro`, `aspnet_bin_exposure`, `baddns_direct`, `generic_ssrf`, `nuclei`, `telerik`.
- Emit `WAF`: `wafw00f`.
- Emit `WEBSCREENSHOT`: `gowitness`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `url-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./url-discovery-yes.yml`

```yaml
description: URL discovery with all modules marked "Should use = Yes"

modules:
  - ajaxpro
  - aspnet_bin_exposure
  - baddns_direct
  - bypass403
  - generic_ssrf
  - git
  - gowitness
  - graphql_introspection
  - httpx
  - iis_shortnames
  - ntlm
  - nuclei
  - portfilter
  - robots
  - smuggler
  - telerik
  - url_manipulation
  - wafw00f
```

## Modules supporting entry event `URL`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| ajaxpro | FINDING | Reference: https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/ | No | Yes, recommended | Yes |
| ajaxpro | VULNERABILITY | Reference: https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/ | No | Yes, recommended | Yes |
| aspnet_bin_exposure | VULNERABILITY | Module `aspnet_bin_exposure` functionality. | No | Yes, recommended | Yes |
| baddns_direct | FINDING | Module `baddns_direct` functionality. | No | Yes, recommended | Yes |
| baddns_direct | VULNERABILITY | Module `baddns_direct` functionality. | No | Yes, recommended | Yes |
| bypass403 | FINDING | Module `bypass403` functionality. | No | Yes, recommended | Yes |
| ffuf | URL_UNVERIFIED | Module `ffuf` functionality. | No | Optional, active fuzzing | Optional |
| generic_ssrf | VULNERABILITY | Module `generic_ssrf` functionality. | No | Yes, recommended | Yes |
| git | CODE_REPOSITORY | Module `git` functionality. | No | Yes, recommended | Yes |
| git | FINDING | Module `git` functionality. | No | Yes, recommended | Yes |
| gowitness | TECHNOLOGY | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| gowitness | URL | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| gowitness | URL_UNVERIFIED | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| gowitness | WEBSCREENSHOT | Module `gowitness` functionality. | No | Yes, recommended | Yes |
| graphql_introspection | FINDING | Module `graphql_introspection` functionality. | No | Yes, recommended | Yes |
| httpx | HTTP_RESPONSE | Module `httpx` functionality. | No | Yes, recommended | Yes |
| httpx | URL | Module `httpx` functionality. | No | Yes, recommended | Yes |
| iis_shortnames | URL_HINT | Module `iis_shortnames` functionality. | No | Yes, recommended | Yes |
| ntlm | DNS_NAME | Todo: | No | Yes, recommended | Yes |
| ntlm | FINDING | Todo: | No | Yes, recommended | Yes |
| nuclei | FINDING | Module `nuclei` functionality. | No | Yes, recommended | Yes |
| nuclei | TECHNOLOGY | Module `nuclei` functionality. | No | Yes, recommended | Yes |
| nuclei | VULNERABILITY | Module `nuclei` functionality. | No | Yes, recommended | Yes |
| portfilter | (none) | Module `portfilter` functionality. | No | Yes, recommended | Yes |
| robots | URL_UNVERIFIED | Module `robots` functionality. | No | Yes, recommended | Yes |
| smuggler | FINDING | Module `smuggler` functionality. | No | Yes, recommended | Yes |
| telerik | FINDING | Test for endpoints associated with Telerik.Web.UI.dll | No | Yes, recommended | Yes |
| telerik | VULNERABILITY | Test for endpoints associated with Telerik.Web.UI.dll | No | Yes, recommended | Yes |
| url_manipulation | FINDING | Module `url_manipulation` functionality. | No | Yes, recommended | Yes |
| vhost | DNS_NAME | Module `vhost` functionality. | No | Optional, active fuzzing | Optional |
| vhost | VHOST | Module `vhost` functionality. | No | Optional, active fuzzing | Optional |
| wafw00f | WAF | https://github.com/EnableSecurity/wafw00f | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
