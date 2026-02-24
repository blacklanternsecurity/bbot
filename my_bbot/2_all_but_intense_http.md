# Generic BBOT Preset: All But Intense HTTP
This page is based on `my_bbot/1_all_included.md`, excluding modules that do deep/intensive work inside URLs (method/parameter/path-heavy probing).  
Goal: keep broad coverage with generic/root URL checks.

## How to use
1. Save the YAML below as `my_bbot/all-but-intense-http.yml`.
2. Export the env vars listed in the env section.
3. Run: `bbot -t example.com -p ./my_bbot/all-but-intense-http.yml`

## Preset config (all included except intense HTTP modules)
```yaml
description: Generic discovery preset excluding deep/intense URL-internal probing modules

modules:
  - apkpure
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
  - domain_phishing
  - dnsreaper
  - docker_pull
  - dockerhub
  - extractous
  - filedownload
  - fingerprintx
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
  - httpx
  - hunterio
  - ipwhois
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
  - nuclei
  - nuclei_takeover
  - oauth
  - otx
  - portfilter
  - postman
  - postman_download
  - rapiddns
  - robots
  - securitytrails
  - shodan_dns
  - shodan_idb
  - social
  - sslcert
  - subzy
  - thc_rdns
  - thc_subdomains
  - trufflehog
  - urlscan
  - virustotal
  - wafw00f
  - wayback

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
| `IPSTACK_API_KEY` | `ipstack` | Enrich IPs with Ipstack geolocation data. |
| `LEAKLOOKUP_API_KEY` | `leaklookup`, `leaklookup_hash` | Query LeakLookup for leaked credentials and hash lookups. |
| `OTX_API_KEY` | `otx` | Query AlienVault OTX for subdomain and OSINT data. |
| `POSTMAN_API_KEY` | `postman` | Access Postman workspaces/collections for discovery. |
| `POSTMAN_DOWNLOAD_API_KEY` | `postman_download` | Download Postman collection content from discovered repos/assets. |
| `SECURITYTRAILS_API_KEY` | `securitytrails` | Query SecurityTrails for subdomain and DNS intelligence. |
| `SHODAN_API_KEY` | `shodan_dns` | Query Shodan DNS datasets for additional hostnames. |
| `VT_API_KEY` | `virustotal` | Query VirusTotal for subdomains and related infrastructure. |

## Optional shell export template
```bash
export CHAOS_API_KEY=""
export DEHASHED_API_KEY=""
export GIT_CLONE_API_KEY=""
export GITHUB_ORG_API_KEY=""
export GITHUB_WORKFLOWS_API_KEY=""
export GITLAB_COM_API_KEY=""
export HUNTERIO_API_KEY=""
export IPSTACK_API_KEY=""
export LEAKLOOKUP_API_KEY=""
export OTX_API_KEY=""
export POSTMAN_API_KEY=""
export POSTMAN_DOWNLOAD_API_KEY=""
export SECURITYTRAILS_API_KEY=""
export SHODAN_API_KEY=""
export VT_API_KEY=""
```

## Excluded intense HTTP modules
`ajaxpro`, `aspnet_bin_exposure`, `bypass403`, `dotnetnuke`, `ffuf_shortnames`, `generic_ssrf`, `graphql_introspection`, `host_header`, `hunt`, `iis_shortnames`, `ntlm`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`, `reflected_parameters`, `retirejs`, `smuggler`, `telerik`, `url_manipulation`, `wpscan`.

## Notes
- This preset keeps generic/root URL checks but removes URL-internal deep probing modules.
- Some modules are still active and can be intensive (`naabu`, `dnsbrute*`, `gowitness`, `trufflehog`, etc.).

## How to run

Build local BBot:

```bash
docker build -f Dockerfile.full -t bbot-local:full .
```

Run scan:
```bash
# run local image with your preset + .env
docker run --rm -it \
  --env-file <(sed -E 's/[[:space:]]+#.*$//' my_bbot/.env | sed '/^[[:space:]]*$/d') \
  -v "$HOME/.bbot/scans:/root/.bbot/scans" \
  -v "$PWD/my_bbot/all-but-intense-http.yml:/preset.yml:ro" \
  bbot-local:full \
  -t <your-target> -p /preset.yml --allow-deadly --no-deps
```
