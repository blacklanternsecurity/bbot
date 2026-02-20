# Generic BBOT Preset: All `Should use = Yes` Modules
This page consolidates all modules marked as `Should use = Yes` across the docs in `my_bbot/*_discovery_modules.md`.

## How to use
1. Save the YAML below as `my_bbot/all-yes-modules.yml`.
2. Export the env vars listed in the env section.
3. Run: `bbot -t example.com -p ./my_bbot/all-yes-modules.yml`
4. Alternative lower-noise HTTP profile: `my_bbot/2_all_but_intense_http.md`

## Preset config (all `Yes` modules)
```yaml
description: Generic discovery preset with all modules marked "Should use = Yes" across my_bbot docs

modules:
  - ajaxpro
  - apkpure
  - aspnet_bin_exposure
  - azure_tenant
  - baddns
  - baddns_direct
  - badsecrets
  - bucket_amazon
  - bucket_digitalocean
  - bucket_file_enum
  - bucket_firebase
  - bucket_google
  - bucket_microsoft
  - bypass403
  - certspotter
  - chaos
  - code_repository
  - crt
  - crt_db
  - dehashed
  - dnsbrute
  - dnsbrute_mutations
  - dnscaa
  - dnscommonsrv
  - dnsdumpster
  - dnsreaper
  - docker_pull
  - dockerhub
  - dotnetnuke
  - extractous
  - ffuf_shortnames
  - filedownload
  - fingerprintx
  - generic_ssrf
  - ggshield
  - git
  - git_clone
  - gitdumper
  - github_org
  - github_workflows
  - gitlab_com
  - gitleaks
  - google_playstore
  - gowitness
  - graphql_introspection
  - host_header
  - httpx
  - hunt
  - hunterio
  - iis_shortnames
  - ip2location
  - ipneighbor
  - ipstack
  - jadx
  - kingfisher
  - leakix
  - leaklookup
  - leaklookup_hash
  - medusa
  - naabu
  - newsletters
  - noseyparker
  - ntlm
  - nuclei
  - nuclei_takeover
  - oauth
  - otx
  - paramminer_cookies
  - paramminer_getparams
  - paramminer_headers
  - portfilter
  - postman
  - postman_download
  - rapiddns
  - reflected_parameters
  - retirejs
  - robots
  - securitytrails
  - shodan_dns
  - shodan_idb
  - smuggler
  - social
  - sslcert
  - subzy
  - telerik
  - thc_rdns
  - thc_subdomains
  - trufflehog
  - url_manipulation
  - urlscan
  - virustotal
  - wafw00f
  - wayback
  - wpscan

config:
  modules:
    chaos:
      api_key: ${env:CHAOS_API_KEY}
    dehashed:
      api_key: ${env:DEHASHED_API_KEY}
    git_clone:
      api_key: ${env:GIT_CLONE_API_KEY}
    github_org:
      api_key: ${env:GITHUB_ORG_API_KEY}
    github_workflows:
      api_key: ${env:GITHUB_WORKFLOWS_API_KEY}
    gitlab_com:
      api_key: ${env:GITLAB_COM_API_KEY}
    hunterio:
      api_key: ${env:HUNTERIO_API_KEY}
    ip2location:
      api_key: ${env:IP2LOCATION_API_KEY}
    ipstack:
      api_key: ${env:IPSTACK_API_KEY}
    leaklookup:
      api_key: ${env:LEAKLOOKUP_API_KEY}
    leaklookup_hash:
      api_key: ${env:LEAKLOOKUP_API_KEY}
    otx:
      api_key: ${env:OTX_API_KEY}
    postman:
      api_key: ${env:POSTMAN_API_KEY}
    postman_download:
      api_key: ${env:POSTMAN_DOWNLOAD_API_KEY}
    securitytrails:
      api_key: ${env:SECURITYTRAILS_API_KEY}
    shodan_dns:
      api_key: ${env:SHODAN_API_KEY}
    virustotal:
      api_key: ${env:VT_API_KEY}
    wpscan:
      api_key: ${env:WPSCAN_API_KEY}
```

## Environment variables needed
| Env var | Used by module(s) | Goal |
|---|---|---|
| `CHAOS_API_KEY` | `chaos` | Query ProjectDiscovery Chaos for subdomain discovery. |
| `DEHASHED_API_KEY` | `dehashed` | Query DeHashed for exposed credentials related to targets. |
| `GIT_CLONE_API_KEY` | `git_clone` | Authenticate repository cloning when required by `git_clone`. |
| `GITHUB_ORG_API_KEY` | `github_org` | Access GitHub org data for repositories and org intelligence. |
| `GITHUB_WORKFLOWS_API_KEY` | `github_workflows` | Access GitHub Actions/workflow artifacts from repositories. |
| `GITLAB_COM_API_KEY` | `gitlab_com` | Access GitLab.com project/org data during social/repo discovery. |
| `HUNTERIO_API_KEY` | `hunterio` | Query Hunter.io for emails and related domains. |
| `IP2LOCATION_API_KEY` | `ip2location` | Enrich IPs with IP2Location geolocation/intelligence data. |
| `IPSTACK_API_KEY` | `ipstack` | Enrich IPs with Ipstack geolocation data. |
| `LEAKLOOKUP_API_KEY` | `leaklookup`, `leaklookup_hash` | Query LeakLookup for leaked credentials and hash lookups. |
| `OTX_API_KEY` | `otx` | Query AlienVault OTX for subdomain and OSINT data. |
| `POSTMAN_API_KEY` | `postman` | Access Postman workspaces/collections for discovery. |
| `POSTMAN_DOWNLOAD_API_KEY` | `postman_download` | Download Postman collection content from discovered repos/assets. |
| `SECURITYTRAILS_API_KEY` | `securitytrails` | Query SecurityTrails for subdomain and DNS intelligence. |
| `SHODAN_API_KEY` | `shodan_dns` | Query Shodan DNS datasets for additional hostnames. |
| `VT_API_KEY` | `virustotal` | Query VirusTotal for subdomains and related infrastructure. |
| `WPSCAN_API_KEY` | `wpscan` | Enable WPScan vulnerability and WordPress tech checks. |

## Optional shell export template
```bash
export CHAOS_API_KEY=""
export DEHASHED_API_KEY=""
export GIT_CLONE_API_KEY=""
export GITHUB_ORG_API_KEY=""
export GITHUB_WORKFLOWS_API_KEY=""
export GITLAB_COM_API_KEY=""
export HUNTERIO_API_KEY=""
export IP2LOCATION_API_KEY=""
export IPSTACK_API_KEY=""
export LEAKLOOKUP_API_KEY=""
export OTX_API_KEY=""
export POSTMAN_API_KEY=""
export POSTMAN_DOWNLOAD_API_KEY=""
export SECURITYTRAILS_API_KEY=""
export SHODAN_API_KEY=""
export VT_API_KEY=""
export WPSCAN_API_KEY=""
```

## Potentially intensive modules (`Yes`) and tuning profiles
These `Yes` modules can become expensive depending on scope, target count, and module params:
`nuclei`, `nuclei_takeover`, `naabu`, `medusa`, `dnsbrute`, `dnsbrute_mutations`, `dnsreaper`, `subzy`, `ffuf_shortnames`, `paramminer_headers`, `paramminer_getparams`, `paramminer_cookies`, `gowitness`, `httpx`, `trufflehog`, `wpscan`.

Use one of these profiles by merging into your preset `config.modules` section.

### Comprehensive mode (higher coverage, higher load)
```yaml
config:
  modules:
    nuclei:
      mode: manual
      tags: ""
      templates: ""
      severity: ""
      etags: ""
      ratelimit: 200
      concurrency: 40
      retries: 1
      batch_size: 400
      directory_only: false
      silent: true
    nuclei_takeover:
      tags: "takeover"
      ratelimit: 200
      concurrency: 40
      retries: 1
      timeout: 10
      silent: true
    naabu:
      top_ports: 1000
      rate: 3000
      threads: 50
      scan_type: c
      retries: 2
      timeout_ms: 1000
      exclude_cdn: false
      scan_all_ips: true
    medusa:
      threads: 10
      timeout_s: 8
      wait_microseconds: 100
    dnsbrute:
      max_depth: 5
    dnsbrute_mutations:
      max_mutations: 500
    dnsreaper:
      parallelism: 80
      disable_probable: false
      enable_unlikely: true
    subzy:
      concurrency: 100
      timeout: 10
      https: true
      verify_ssl: false
    ffuf_shortnames:
      max_depth: 2
      max_predictions: 500
      rate: 0
      find_common_prefixes: true
      find_delimiters: true
      find_subwords: true
    paramminer_headers:
      recycle_words: true
      skip_boring_words: false
    paramminer_getparams:
      recycle_words: true
      skip_boring_words: false
    paramminer_cookies:
      recycle_words: true
      skip_boring_words: false
    gowitness:
      threads: 16
      timeout: 15
      resolution_x: 1920
      resolution_y: 1080
      social: true
      idle_timeout: 1800
    httpx:
      threads: 100
      in_scope_only: false
      max_response_size: 5242880
      store_responses: true
      probe_all_ips: true
    trufflehog:
      only_verified: false
      concurrency: 16
      deleted_forks: false
    wpscan:
      enumerate: "vp,ap,vt,at,tt,cb,dbe,u,m"
      threads: 10
      request_timeout: 10
      connection_timeout: 5
      disable_tls_checks: true
      force: false
```


### Controlled mode (safer/default for broad scopes)
```yaml
config:
  modules:
    nuclei:
      mode: severe
      ratelimit: 30
      concurrency: 5
      retries: 0
      batch_size: 50
      directory_only: true
      silent: true
    nuclei_takeover:
      tags: "takeover"
      ratelimit: 30
      concurrency: 5
      retries: 0
      timeout: 8
      silent: true
    naabu:
      top_ports: 100
      rate: 300
      threads: 10
      scan_type: c
      retries: 1
      timeout_ms: 1500
      exclude_cdn: true
      scan_all_ips: false
    medusa:
      threads: 2
      timeout_s: 3
      wait_microseconds: 800
    dnsbrute:
      max_depth: 2
    dnsbrute_mutations:
      max_mutations: 30
    dnsreaper:
      parallelism: 20
      disable_probable: false
      enable_unlikely: false
    subzy:
      concurrency: 20
      timeout: 8
      https: true
      verify_ssl: false
    ffuf_shortnames:
      max_depth: 1
      max_predictions: 80
      rate: 50
      find_common_prefixes: false
      find_delimiters: true
      find_subwords: false
    paramminer_headers:
      recycle_words: false
      skip_boring_words: true
    paramminer_getparams:
      recycle_words: false
      skip_boring_words: true
    paramminer_cookies:
      recycle_words: false
      skip_boring_words: true
    gowitness:
      threads: 4
      timeout: 7
      resolution_x: 1280
      resolution_y: 720
      social: false
      idle_timeout: 600
    httpx:
      threads: 20
      in_scope_only: true
      max_response_size: 1048576
      store_responses: false
      probe_all_ips: false
    trufflehog:
      only_verified: true
      concurrency: 4
      deleted_forks: false
    wpscan:
      enumerate: "vp,vt"
      threads: 2
      request_timeout: 4
      connection_timeout: 2
      disable_tls_checks: true
      force: false
```


## Notes
- This is a union preset. Running all modules at once can be noisy and slower than using event-specific presets.
- Some modules are active/scanning modules; use your normal authorization and scope controls.
- Takeover additions included in this preset: `dnsreaper`, `nuclei_takeover`, and `subzy`.
