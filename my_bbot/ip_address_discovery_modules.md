# Discovery modules for entry event `IP_ADDRESS` (BBOT)
This doc is entry-event based and lists modules that support `IP_ADDRESS` input and the events they emit.

## Entry event model
- Entry event: `IP_ADDRESS`
- Selection rule: modules that consume `IP_ADDRESS` (`watched_events`) and list outputs from `produced_events`

## Quick start (recommended)
- Run with a focused set of `IP_ADDRESS` modules (example):
  - `bbot -t example.com -m ip2location ipneighbor ipstack naabu portscan`
- If the chosen modules are passive-capable, you can force passive mode:
  - `bbot -t example.com -m ip2location ipneighbor ipstack naabu portscan -rf passive`

## Enable a specific set of `IP_ADDRESS` modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m ip2location ipneighbor ipstack naabu portscan`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -m ip2location ipneighbor ipstack naabu portscan -c modules.<module>.api_key=YOURKEY`

## What these modules do
- Grouped by emitted event type:
- Emit `DNS_NAME`: `censys_ip`, `shodan_idb`, `thc_rdns`.
- Emit `FINDING`: `shodan_idb`.
- Emit `GEOLOCATION`: `ip2location`, `ipstack`.
- Emit `IP_ADDRESS`: `censys_ip`, `ipneighbor`.
- Emit `OPEN_TCP_PORT`: `censys_ip`, `naabu`, `portscan`, `shodan_idb`.
- Emit `OPEN_UDP_PORT`: `censys_ip`.
- Emit `PROTOCOL`: `censys_ip`.
- Emit `TECHNOLOGY`: `censys_ip`, `shodan_idb`.
- Emit `URL_UNVERIFIED`: `censys_ip`.
- Emit `VULNERABILITY`: `shodan_idb`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `ip_address-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./ip_address-discovery-yes.yml`

```yaml
description: IP_ADDRESS discovery with all modules marked "Should use = Yes"

modules:
  - ip2location
  - ipneighbor
  - ipstack
  - shodan_idb
  - thc_rdns

config:
  modules:
    ip2location:
      api_key: ${env:IP2LOCATION_API_KEY}
    ipstack:
      api_key: ${env:IPSTACK_API_KEY}
```

## Modules supporting entry event `IP_ADDRESS`
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| censys_ip | DNS_NAME | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| censys_ip | IP_ADDRESS | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| censys_ip | OPEN_TCP_PORT | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| censys_ip | OPEN_UDP_PORT | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| censys_ip | PROTOCOL | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| censys_ip | TECHNOLOGY | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| censys_ip | URL_UNVERIFIED | Query the Censys /v2/hosts/{ip} endpoint for associated hostnames, IPs, and URLs. | Yes | No, disabled by policy | No |
| ip2location | GEOLOCATION | IP2Location.io Geolocation API. | Yes | Yes, recommended | Yes |
| ipneighbor | IP_ADDRESS | Module `ipneighbor` functionality. | No | Yes, recommended | Yes |
| ipstack | GEOLOCATION | Ipstack GeoIP | Yes | Yes, recommended | Yes |
| naabu | OPEN_TCP_PORT | Module `naabu` functionality. | No | Optional, active port scan | Optional |
| portscan | OPEN_TCP_PORT | Module `portscan` functionality. | No | Optional, active port scan | Optional |
| shodan_idb | DNS_NAME | Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities | No | Yes, 1 life payment | Yes |
| shodan_idb | FINDING | Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities | No | Yes, 1 life payment | Yes |
| shodan_idb | OPEN_TCP_PORT | Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities | No | Yes, 1 life payment | Yes |
| shodan_idb | TECHNOLOGY | Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities | No | Yes, 1 life payment | Yes |
| shodan_idb | VULNERABILITY | Query IP in Shodan InternetDB, returning open ports, discovered technologies, and findings/vulnerabilities | No | Yes, 1 life payment | Yes |
| thc_rdns | DNS_NAME | Module `thc_rdns` functionality. | No | Yes, recommended | Yes |

## Notes
- This list is auto-generated from `bbot/modules/*.py` class metadata (`watched_events` and `produced_events`).
- `Should use` is curated in this table and drives the preset module list above.
