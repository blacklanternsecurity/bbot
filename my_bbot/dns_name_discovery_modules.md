# Subdomain discovery modules (BBOT)
This doc is entry-event based and lists modules that support `DNS_NAME` input to discover subdomains/related domains and other enrichment events.

## Entry event model
- Entry event: `DNS_NAME`
- Selection rule: modules that consume `DNS_NAME` and emit discovery/enrichment events

## Quick start (recommended)
- Run the built-in preset (enables all `subdomain-enum` modules):
  - `bbot -t example.com -p subdomain-enum`
- Passive-only (no brute-force):
  - `bbot -t example.com -p subdomain-enum -rf passive`

## Enable a specific set of subdomain modules
Use `-m` to list modules explicitly (example):
`bbot -t example.com -m crt chaos securitytrails shodan_dns dnsbrute`

## API keys
Put keys in your config (or pass via `-c`):
- Example: `bbot -t example.com -p subdomain-enum -c modules.chaos.api_key=YOURKEY`

## What these modules do
- Certificate transparency and internet datasets:
`crt`, `crt_db`, `certspotter`, `anubisdb`, `dnsdumpster`, `rapiddns`, `urlscan`, `wayback`, `sitedossier`, `digitorus`, `leakix`.
- Commercial/provider APIs:
`securitytrails`, `shodan_dns`, `censys_dns`, `virustotal`, `otx`, `passivetotal`, `fullhunt`, `subdomainradar`, `trickest`, `builtwith`, `bevigil`, `c99`, `bufferoverrun`.
- Active discovery:
`dnsbrute`, `dnsbrute_mutations`, `dnscommonsrv`.
- Subdomain takeover checks:
`baddns`, `dnsreaper`, `nuclei_takeover`, `subzy`.
- Relationship/affiliate expansion:
`azure_tenant`, `viewdns`, `thc_cnames`.
- Mixed modules that also emit other event types:
`dnscaa`, `hunterio`, `shodan_idb`, `dehashed`, `leaklookup`.

## Preset config enabling all `Should use = Yes` modules
Save this as a preset, for example `subdomain-discovery-yes.yml`, and run with:
`bbot -t example.com -p ./subdomain-discovery-yes.yml`

```yaml
description: Subdomain discovery with all modules marked "Should use = Yes"

modules:
  - azure_tenant
  - certspotter
  - chaos
  - crt
  - crt_db
  - dnsbrute
  - dnsbrute_mutations
  - dnscaa
  - dnscommonsrv
  - dnsdumpster
  - dnsreaper
  - hunterio
  - leakix
  - nuclei_takeover
  - otx
  - rapiddns
  - securitytrails
  - shodan_dns
  - shodan_idb
  - thc_subdomains
  - subzy
  - dehashed
  - leaklookup
  - urlscan
  - virustotal
  - wayback

config:
  modules:
    chaos:
      api_key: ${env:CHAOS_API_KEY}
    hunterio:
      api_key: ${env:HUNTERIO_API_KEY}
    otx:
      api_key: ${env:OTX_API_KEY}
    dehashed:
      api_key: ${env:DEHASHED_API_KEY}
    leaklookup:
      api_key: ${env:LEAKLOOKUP_API_KEY}
    securitytrails:
      api_key: ${env:SECURITYTRAILS_API_KEY}
    shodan_dns:
      api_key: ${env:SHODAN_API_KEY}
    virustotal:
      api_key: ${env:VT_API_KEY}
```

## Modules supporting entry event `DNS_NAME` for subdomain discovery
| Module | Emitted event | What it does (1 sentence) | Needs API key | Notes | Should use |
|---|---|---|---:|---|---:|
| anubisdb | DNS_NAME | Query jldc.me's database for subdomains | No | No, low value | No |
| azure_tenant | DNS_NAME | Query Azure via azmap.dev for tenant sister domains | No | Yes, recommended | Yes |
| bevigil | DNS_NAME | Retrieve OSINT data from mobile applications using BeVigil | Yes | No, too expensive | No |
| bevigil | URL_UNVERIFIED | Retrieve OSINT data from mobile applications using BeVigil | Yes | No, too expensive | No |
| bufferoverrun | DNS_NAME | Query BufferOverrun's TLS API for subdomains | Yes | No, too expensive | No |
| builtwith | DNS_NAME | Query Builtwith.com for subdomains | Yes | No, too expensive | No |
| c99 | DNS_NAME | Query the C99 API for subdomains | Yes | No, too expensive | No |
| censys_dns | DNS_NAME | Query the Censys API for subdomains | Yes | No, too expensive | No |
| certspotter | DNS_NAME | Query Certspotter's API for subdomains | No | Yes, recommended | Yes |
| chaos | DNS_NAME | Query ProjectDiscovery's Chaos API for subdomains | Yes | Yes, recommended | Yes |
| crt | DNS_NAME | Query crt.sh (certificate transparency) for subdomains | No | Yes, recommended | Yes |
| crt_db | DNS_NAME | Query crt.sh (certificate transparency) for subdomains via PostgreSQL | No | Yes, recommended | Yes |
| digitorus | DNS_NAME | Query certificatedetails.com for subdomains | No | No, low value | No |
| dnscaa | DNS_NAME | Check for CAA records | No | Yes, recommended | Yes |
| dnscaa | EMAIL_ADDRESS | Check for CAA records | No | Yes, recommended | Yes |
| dnscaa | URL_UNVERIFIED | Check for CAA records | No | Yes, recommended | Yes |
| dnsbrute | DNS_NAME | Brute-force subdomains with massdns + static wordlist | No | Yes, recommended | Yes |
| dnsbrute_mutations | DNS_NAME | Brute-force subdomains with massdns + target-specific mutations | No | Yes, recommended | Yes |
| dnscommonsrv | DNS_NAME | Check for common SRV records | No | Yes, recommended | Yes |
| dnsdumpster | DNS_NAME | Query dnsdumpster for subdomains | No | Yes, recommended | Yes |
| dnsreaper | FINDING | Check potential subdomain takeovers with dnsReaper | No | Yes, recommended | Yes |
| dnsreaper | VULNERABILITY | Check potential subdomain takeovers with dnsReaper | No | Yes, recommended | Yes |
| fullhunt | DNS_NAME | Query the fullhunt.io API for subdomains | Yes | No, too expensive | No |
| hackertarget | DNS_NAME | Query the hackertarget.com API for subdomains | No | No, too expensive | No |
| hunterio | EMAIL_ADDRESS | Query hunter.io for emails and related domains | Yes | Yes, free trial | Yes |
| hunterio | DNS_NAME | Query hunter.io for emails and related domains | Yes | Yes, free trial | Yes |
| hunterio | URL_UNVERIFIED | Query hunter.io for emails and related domains | Yes | Yes, free trial | Yes |
| leakix | DNS_NAME | Query leakix.net for subdomains | No | Yes, recommended | Yes |
| myssl | DNS_NAME | Query myssl.com's API for subdomains | No | No, too expensive | No |
| nuclei_takeover | FINDING | Run nuclei takeover templates (`-tags takeover`) against discovered hostnames | No | Yes, recommended | Yes |
| nuclei_takeover | VULNERABILITY | Run nuclei takeover templates (`-tags takeover`) against discovered hostnames | No | Yes, recommended | Yes |
| otx | DNS_NAME | Query otx.alienvault.com for subdomains | Yes | Yes, free trial | Yes |
| passivetotal | DNS_NAME | Query the PassiveTotal API for subdomains | Yes | No, too expensive | No |
| rapiddns | DNS_NAME | Query rapiddns.io for subdomains | No | Yes, recommended | Yes |
| securitytrails | DNS_NAME | Query the SecurityTrails API for subdomains | Yes | Yes, free trial | Yes |
| shodan_dns | DNS_NAME | Query Shodan for subdomains | Yes | Yes, 1 time pay | Yes |
| shodan_idb | TECHNOLOGY | Query Shodan InternetDB for hostnames and service context | No | Yes, 1 time pay | Yes |
| shodan_idb | VULNERABILITY | Query Shodan InternetDB for hostnames and service context | No | Yes, 1 time pay | Yes |
| shodan_idb | FINDING | Query Shodan InternetDB for hostnames and service context | No | Yes, 1 time pay | Yes |
| shodan_idb | OPEN_TCP_PORT | Query Shodan InternetDB for hostnames and service context | No | Yes, 1 time pay | Yes |
| shodan_idb | DNS_NAME | Query Shodan InternetDB for hostnames and service context | No | Yes, 1 time pay | Yes |
| sitedossier | DNS_NAME | Query sitedossier.com for subdomains | No | No, not working | No |
| subdomaincenter | DNS_NAME | Query subdomain.center's API for subdomains | No | No, too expensive | No |
| subdomainradar | DNS_NAME | Query the Subdomain API for subdomains | Yes | No, too expensive | No |
| subzy | VULNERABILITY | Check potential subdomain takeovers with subzy | No | Yes, recommended | Yes |
| thc_cnames | DNS_NAME | Query ip.thc.org for domains CNAME'd to a target domain | No | No, low value | No |
| thc_subdomains | DNS_NAME | Query ip.thc.org for subdomains | No | Yes, recommended | Yes |
| trickest | DNS_NAME | Query Trickest's API for subdomains | Yes | No, too expensive | No |
| urlscan | DNS_NAME | Query urlscan.io for subdomains | No | Yes, recommended | Yes |
| urlscan | URL_UNVERIFIED | Query urlscan.io for subdomains | No | Yes, recommended | Yes |
| viewdns | DNS_NAME | Query viewdns.info's reverse whois for related domains | No | Optional, affiliate expansion | Optional |
| virustotal | DNS_NAME | Query VirusTotal's API for subdomains | Yes | Yes, free trial | Yes |
| wayback | URL_UNVERIFIED | Query archive.org's API for subdomains | No | Yes, recommended | Yes |
| wayback | DNS_NAME | Query archive.org's API for subdomains | No | Yes, recommended | Yes |
| dehashed | EMAIL_ADDRESS | Execute queries against dehashed.com for exposed credentials | Yes | Yes, paid API | Yes |
| dehashed | HASHED_PASSWORD | Execute queries against dehashed.com for exposed credentials | Yes | Yes, paid API | Yes |
| dehashed | PASSWORD | Execute queries against dehashed.com for exposed credentials | Yes | Yes, paid API approved | Yes |
| dehashed | USERNAME | Execute queries against dehashed.com for exposed credentials | Yes | Yes, paid API approved | Yes |
| leaklookup | EMAIL_ADDRESS | Query leak-lookup.com for leaked credentials and crack hashes | Yes | Yes, paid API approved | Yes |
| leaklookup | HASHED_PASSWORD | Query leak-lookup.com for leaked credentials and crack hashes | Yes | Yes, paid API approved | Yes |
| leaklookup | PASSWORD | Query leak-lookup.com for leaked credentials and crack hashes | Yes | Yes, paid API approved | Yes |
| leaklookup | USERNAME | Query leak-lookup.com for leaked credentials and crack hashes | Yes | Yes, paid API approved | Yes |

## Notes
- This list is strictly entry-event based (`DNS_NAME` input).
- `thc_cnames` and `viewdns` are often affiliate/related-domain expansion rather than strict child-subdomain discovery.
