# Discovery modules for entry event `DNS_NAME_UNRESOLVED` (BBOT)
This doc is entry-event based and lists modules that support `DNS_NAME_UNRESOLVED` input and the events they emit.

## Entry event model
- Entry event: `DNS_NAME_UNRESOLVED`
- Selection rule: modules that consume `DNS_NAME_UNRESOLVED` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `DNS_NAME_UNRESOLVED` modules (example):
  - `bbot -t example.com -m baddns dnsreaper nuclei_takeover subzy`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m baddns dnsreaper nuclei_takeover subzy -rf passive`

## Enable a specific set of `DNS_NAME_UNRESOLVED` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m baddns dnsreaper nuclei_takeover subzy`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m baddns -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `FINDING`: `baddns`, `dnsreaper`, `nuclei_takeover`.
- Emit `VULNERABILITY`: `baddns`, `dnsreaper`, `nuclei_takeover`, `subzy`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `dns_name_unresolved-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./dns_name_unresolved-discovery-yes.yml`

```yaml
description: DNS_NAME_UNRESOLVED discovery with all modules marked "Should use = Yes"

modules:
  - baddns
  - dnsreaper
  - nuclei_takeover
  - subzy
```

## Modules supporting entry event `DNS_NAME_UNRESOLVED`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| baddns | FINDING | Module `baddns` functionality. | No | Yes, recommended | Yes |
| baddns | VULNERABILITY | Module `baddns` functionality. | No | Yes, recommended | Yes |
| dnsreaper | FINDING | Check potential subdomain takeovers with dnsReaper | No | Yes, recommended | Yes |
| dnsreaper | VULNERABILITY | Check potential subdomain takeovers with dnsReaper | No | Yes, recommended | Yes |
| nuclei_takeover | FINDING | Run nuclei takeover templates (`-tags takeover`) against discovered hostnames | No | Yes, recommended | Yes |
| nuclei_takeover | VULNERABILITY | Run nuclei takeover templates (`-tags takeover`) against discovered hostnames | No | Yes, recommended | Yes |
| subzy | VULNERABILITY | Check potential subdomain takeovers with subzy | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
