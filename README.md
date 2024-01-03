[![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)](https://github.com/blacklanternsecurity/bbot)

# BEE·bot

### OSINT automation for hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![DEF CON Demo Labs 2023](https://img.shields.io/badge/DEF%20CON%20Demo%20Labs-2023-FF8400.svg)](https://forum.defcon.org/node/246338) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Pypi Downloads](https://img.shields.io/pypi/dm/bbot)](https://pypistats.org/packages/bbot) [![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

BBOT (Bighuge BLS OSINT Tool) is a modular, recursive OSINT framework that can execute the entire OSINT workflow in a single command.

BBOT is inspired by [Spiderfoot](https://github.com/smicallef/spiderfoot) but takes it to the next level with features like multi-target scans, lightning-fast asyncio performance, and NLP-powered subdomain mutations. It offers a wide range of functionality, including subdomain enumeration, port scanning, web screenshots, vulnerability scanning, and much more. 

![subdomain-stats-boeing](https://github.com/blacklanternsecurity/bbot/assets/20261699/de0154c1-476e-4337-9599-45a1c5e0e78b)

BBOT typically outperforms other subdomain enumeration tools by 20-25%. To learn how this is possible, see [How It Works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

## Full Documentation [Here](https://www.blacklanternsecurity.com/bbot/).

## Installation ([pip](https://pypi.org/project/bbot/))

Note: Requires Linux and Python 3.9+.

```bash
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot

bbot --help
```

## Installation ([Docker](https://hub.docker.com/r/blacklanternsecurity/bbot))

Docker images are provided, along with helper script `bbot-docker.sh` to persist your scan data.

```bash
# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help

# helper script
git clone https://github.com/blacklanternsecurity/bbot && cd bbot
./bbot-docker.sh --help
```


## Example Commands

Scan output, logs, etc. are saved to `~/.bbot`. For more detailed examples and explanations, see [Scanning](https://www.blacklanternsecurity.com/bbot/scanning).

<!-- BBOT EXAMPLE COMMANDS -->
**Subdomains:**

```bash
# Perform a full subdomain enumeration on evilcorp.com
bbot -t evilcorp.com -f subdomain-enum
```

**Subdomains (passive only):**

```bash
# Perform a passive-only subdomain enumeration on evilcorp.com
bbot -t evilcorp.com -f subdomain-enum -rf passive
```

**Subdomains + port scan + web screenshots:**

```bash
# Port-scan every subdomain, screenshot every webpage, output to current directory
bbot -t evilcorp.com -f subdomain-enum -m nmap gowitness -n my_scan -o .
```

**Subdomains + basic web scan:**

```bash
# A basic web scan includes wappalyzer, robots.txt, and other non-intrusive web modules
bbot -t evilcorp.com -f subdomain-enum web-basic
```

**Web spider:**

```bash
# Crawl www.evilcorp.com up to a max depth of 2, automatically extracting emails, secrets, etc.
bbot -t www.evilcorp.com -m httpx robots badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2
```

**Everything everywhere all at once:**

```bash
# Subdomains, emails, cloud buckets, port scan, basic web, web screenshots, nuclei
bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly
```
<!-- END BBOT EXAMPLE COMMANDS -->

## Targets

BBOT accepts an unlimited number of targets via `-t`. You can specify targets either directly on the command line or in files (or both!). Targets can be any of the following:

- `DNS_NAME` (`evilcorp.com`)
- `IP_ADDRESS` (`1.2.3.4`)
- `IP_RANGE` (`1.2.3.0/24`)
- `OPEN_TCP_PORT` (`192.168.0.1:80`)
- `URL` (`https://www.evilcorp.com`)

For more information, see [Targets](https://www.blacklanternsecurity.com/bbot/scanning/#targets-t). To learn how BBOT handles scope, see [Scope](https://www.blacklanternsecurity.com/bbot/scanning/#scope).

## API Keys

Similar to Amass or Subfinder, BBOT supports API keys for various third-party services such as SecurityTrails, etc.

The standard way to do this is to enter your API keys in **`~/.config/bbot/secrets.yml`**:
```yaml
modules:
  shodan_dns:
    api_key: 4f41243847da693a4f356c0486114bc6
  c99:
    api_key: 21a270d5f59c9b05813a72bb41707266
  virustotal:
    api_key: dd5f0eee2e4a99b71a939bded450b246
  securitytrails:
    api_key: d9a05c3fd9a514497713c54b4455d0b0
```

If you like, you can also specify them on the command line:
```bash
bbot -c modules.virustotal.api_key=dd5f0eee2e4a99b71a939bded450b246
```

For details, see [Configuration](https://www.blacklanternsecurity.com/bbot/scanning/configuration/)

## BBOT as a Python library

BBOT exposes a Python API that allows it to be used for all kinds of fun and nefarious purposes, like a [Discord Bot](https://www.blacklanternsecurity.com/bbot/dev/#bbot-python-library-advanced-usage#discord-bot-example) that responds to the `/scan` command.

![bbot-discord](https://github.com/blacklanternsecurity/bbot/assets/20261699/22b268a2-0dfd-4c2a-b7c5-548c0f2cc6f9)

**Synchronous**

```python
from bbot.scanner import Scanner

# any number of targets can be specified
scan = Scanner("example.com", "scanme.nmap.org", modules=["nmap", "sslcert"])
for event in scan.start():
    print(event.json())
```

**Asynchronous**

```python
from bbot.scanner import Scanner

async def main():
    scan = Scanner("example.com", "scanme.nmap.org", modules=["nmap", "sslcert"])
    async for event in scan.async_start():
        print(event.json())

import asyncio
asyncio.run(main())
```

## Documentation

<!-- BBOT DOCS TOC -->
- **Basics**
    - [Getting Started](https://www.blacklanternsecurity.com/bbot/)
    - [How it Works](https://www.blacklanternsecurity.com/bbot/how_it_works)
    - [Comparison to Other Tools](https://www.blacklanternsecurity.com/bbot/comparison)
- **Scanning**
    - [Scanning Overview](https://www.blacklanternsecurity.com/bbot/scanning/)
    - [Events](https://www.blacklanternsecurity.com/bbot/scanning/events)
    - [Output](https://www.blacklanternsecurity.com/bbot/scanning/output)
    - [Tips and Tricks](https://www.blacklanternsecurity.com/bbot/scanning/tips_and_tricks)
    - [Advanced Usage](https://www.blacklanternsecurity.com/bbot/scanning/advanced)
    - [Configuration](https://www.blacklanternsecurity.com/bbot/scanning/configuration)
- **Modules**
    - [List of Modules](https://www.blacklanternsecurity.com/bbot/modules/list_of_modules)
    - [Nuclei](https://www.blacklanternsecurity.com/bbot/modules/nuclei)
- **Contribution**
    - [How to Write a Module](https://www.blacklanternsecurity.com/bbot/contribution)
- **Misc**
    - [Release History](https://www.blacklanternsecurity.com/bbot/release_history)
    - [Troubleshooting](https://www.blacklanternsecurity.com/bbot/troubleshooting)
<!-- END BBOT DOCS TOC -->

## Contribution

BBOT is constantly being improved by the community. Every day it grows more powerful!

We welcome contributions. Not just code, but ideas too! If you have an idea for a new feature, please let us know in [Discussions](https://github.com/blacklanternsecurity/bbot/discussions). If you want to get your hands dirty, see [Contribution](https://www.blacklanternsecurity.com/bbot/contribution/). There you can find setup instructions and a simple tutorial on how to write a BBOT module. We also have extensive [Developer Documentation](https://www.blacklanternsecurity.com/bbot/dev/).

Thanks to these amazing people for contributing to BBOT! :heart:

<p align="center">
<a href="https://github.com/blacklanternsecurity/bbot/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=blacklanternsecurity/bbot&max=500">
</a>
</p>

Special thanks to the following people who made BBOT possible:

- @TheTechromancer for creating [BBOT](https://github.com/blacklanternsecurity/bbot)
- @liquidsec for his extensive work on BBOT's web hacking features, including [badsecrets](https://github.com/blacklanternsecurity/badsecrets)
- Steve Micallef (@smicallef) for creating Spiderfoot
- @kerrymilan for his Neo4j and Ansible expertise
- Aleksei Kornev (@alekseiko) for allowing us ownership of the bbot Pypi repository <3

## List of BBOT Modules
<!-- BBOT MODULES -->
| Module               | Type     | Needs API Key   | Description                                                                                                                             | Flags                                                                               | Consumed Events                                                                                                               | Produced Events                                             |
|----------------------|----------|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| ajaxpro              | scan     | No              | Check for potentially vulnerable Ajaxpro instances                                                                                      | active, safe, web-thorough                                                          | HTTP_RESPONSE, URL                                                                                                            | FINDING, VULNERABILITY                                      |
| badsecrets           | scan     | No              | Library for detecting known or weak secrets across many web frameworks                                                                  | active, safe, web-basic, web-thorough                                               | HTTP_RESPONSE                                                                                                                 | FINDING, VULNERABILITY                                      |
| bucket_amazon        | scan     | No              | Check for S3 buckets related to target                                                                                                  | active, cloud-enum, safe, web-basic, web-thorough                                   | DNS_NAME, STORAGE_BUCKET                                                                                                      | FINDING, STORAGE_BUCKET                                     |
| bucket_azure         | scan     | No              | Check for Azure storage blobs related to target                                                                                         | active, cloud-enum, safe, web-basic, web-thorough                                   | DNS_NAME, STORAGE_BUCKET                                                                                                      | FINDING, STORAGE_BUCKET                                     |
| bucket_digitalocean  | scan     | No              | Check for DigitalOcean spaces related to target                                                                                         | active, cloud-enum, safe, slow, web-thorough                                        | DNS_NAME, STORAGE_BUCKET                                                                                                      | FINDING, STORAGE_BUCKET                                     |
| bucket_firebase      | scan     | No              | Check for open Firebase databases related to target                                                                                     | active, cloud-enum, safe, web-basic, web-thorough                                   | DNS_NAME, STORAGE_BUCKET                                                                                                      | FINDING, STORAGE_BUCKET                                     |
| bucket_google        | scan     | No              | Check for Google object storage related to target                                                                                       | active, cloud-enum, safe, web-basic, web-thorough                                   | DNS_NAME, STORAGE_BUCKET                                                                                                      | FINDING, STORAGE_BUCKET                                     |
| bypass403            | scan     | No              | Check 403 pages for common bypasses                                                                                                     | active, aggressive, web-thorough                                                    | URL                                                                                                                           | FINDING                                                     |
| dastardly            | scan     | No              | Lightweight web application security scanner                                                                                            | active, aggressive, deadly, slow, web-thorough                                      | HTTP_RESPONSE                                                                                                                 | FINDING, VULNERABILITY                                      |
| dnszonetransfer      | scan     | No              | Attempt DNS zone transfers                                                                                                              | active, safe, subdomain-enum                                                        | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| ffuf                 | scan     | No              | A fast web fuzzer written in Go                                                                                                         | active, aggressive, deadly                                                          | URL                                                                                                                           | URL_UNVERIFIED                                              |
| ffuf_shortnames      | scan     | No              | Use ffuf in combination IIS shortnames                                                                                                  | active, aggressive, iis-shortnames, web-thorough                                    | URL_HINT                                                                                                                      | URL_UNVERIFIED                                              |
| filedownload         | scan     | No              | Download common filetypes such as PDF, DOCX, PPTX, etc.                                                                                 | active, safe, web-basic                                                             | HTTP_RESPONSE, URL_UNVERIFIED                                                                                                 |                                                             |
| fingerprintx         | scan     | No              | Fingerprint exposed services like RDP, SSH, MySQL, etc.                                                                                 | active, safe, service-enum, slow                                                    | OPEN_TCP_PORT                                                                                                                 | PROTOCOL                                                    |
| generic_ssrf         | scan     | No              | Check for generic SSRFs                                                                                                                 | active, aggressive, web-thorough                                                    | URL                                                                                                                           | VULNERABILITY                                               |
| git                  | scan     | No              | Check for exposed .git repositories                                                                                                     | active, safe, web-basic, web-thorough                                               | URL                                                                                                                           | FINDING                                                     |
| gowitness            | scan     | No              | Take screenshots of webpages                                                                                                            | active, safe, web-screenshots                                                       | URL                                                                                                                           | TECHNOLOGY, URL, URL_UNVERIFIED, WEBSCREENSHOT              |
| host_header          | scan     | No              | Try common HTTP Host header spoofing techniques                                                                                         | active, aggressive, web-thorough                                                    | HTTP_RESPONSE                                                                                                                 | FINDING                                                     |
| httpx                | scan     | No              | Visit webpages. Many other modules rely on httpx                                                                                        | active, cloud-enum, safe, social-enum, subdomain-enum, web-basic, web-thorough      | OPEN_TCP_PORT, URL, URL_UNVERIFIED                                                                                            | HTTP_RESPONSE, URL                                          |
| hunt                 | scan     | No              | Watch for commonly-exploitable HTTP parameters                                                                                          | active, safe, web-thorough                                                          | HTTP_RESPONSE                                                                                                                 | FINDING                                                     |
| iis_shortnames       | scan     | No              | Check for IIS shortname vulnerability                                                                                                   | active, iis-shortnames, safe, web-basic, web-thorough                               | URL                                                                                                                           | URL_HINT                                                    |
| masscan              | scan     | No              | Port scan with masscan. By default, scans top 100 ports.                                                                                | active, aggressive, portscan                                                        | IP_ADDRESS, IP_RANGE                                                                                                          | OPEN_TCP_PORT                                               |
| nmap                 | scan     | No              | Port scan with nmap. By default, scans top 100 ports.                                                                                   | active, aggressive, portscan, web-thorough                                          | DNS_NAME, IP_ADDRESS, IP_RANGE                                                                                                | OPEN_TCP_PORT                                               |
| ntlm                 | scan     | No              | Watch for HTTP endpoints that support NTLM authentication                                                                               | active, safe, web-basic, web-thorough                                               | HTTP_RESPONSE, URL                                                                                                            | DNS_NAME, FINDING                                           |
| nuclei               | scan     | No              | Fast and customisable vulnerability scanner                                                                                             | active, aggressive, deadly                                                          | URL                                                                                                                           | FINDING, VULNERABILITY                                      |
| oauth                | scan     | No              | Enumerate OAUTH and OpenID Connect services                                                                                             | active, affiliates, cloud-enum, safe, subdomain-enum, web-basic                     | DNS_NAME, URL_UNVERIFIED                                                                                                      | DNS_NAME                                                    |
| paramminer_cookies   | scan     | No              | Smart brute-force to check for common HTTP cookie parameters                                                                            | active, aggressive, slow, web-paramminer                                            | HTTP_RESPONSE                                                                                                                 | FINDING                                                     |
| paramminer_getparams | scan     | No              | Use smart brute-force to check for common HTTP GET parameters                                                                           | active, aggressive, slow, web-paramminer                                            | HTTP_RESPONSE                                                                                                                 | FINDING                                                     |
| paramminer_headers   | scan     | No              | Use smart brute-force to check for common HTTP header parameters                                                                        | active, aggressive, slow, web-paramminer                                            | HTTP_RESPONSE                                                                                                                 | FINDING                                                     |
| robots               | scan     | No              | Look for and parse robots.txt                                                                                                           | active, safe, web-basic, web-thorough                                               | URL                                                                                                                           | URL_UNVERIFIED                                              |
| secretsdb            | scan     | No              | Detect common secrets with secrets-patterns-db                                                                                          | active, safe, web-basic, web-thorough                                               | HTTP_RESPONSE                                                                                                                 | FINDING                                                     |
| smuggler             | scan     | No              | Check for HTTP smuggling                                                                                                                | active, aggressive, slow, web-thorough                                              | URL                                                                                                                           | FINDING                                                     |
| sslcert              | scan     | No              | Visit open ports and retrieve SSL certificates                                                                                          | active, affiliates, email-enum, safe, subdomain-enum, web-basic, web-thorough       | OPEN_TCP_PORT                                                                                                                 | DNS_NAME, EMAIL_ADDRESS                                     |
| subdomain_hijack     | scan     | No              | Detect hijackable subdomains                                                                                                            | active, cloud-enum, safe, subdomain-enum, subdomain-hijack, web-basic, web-thorough | DNS_NAME, DNS_NAME_UNRESOLVED                                                                                                 | FINDING                                                     |
| telerik              | scan     | No              | Scan for critical Telerik vulnerabilities                                                                                               | active, aggressive, web-thorough                                                    | HTTP_RESPONSE, URL                                                                                                            | FINDING, VULNERABILITY                                      |
| url_manipulation     | scan     | No              | Attempt to identify URL parsing/routing based vulnerabilities                                                                           | active, aggressive, web-thorough                                                    | URL                                                                                                                           | FINDING                                                     |
| vhost                | scan     | No              | Fuzz for virtual hosts                                                                                                                  | active, aggressive, deadly, slow                                                    | URL                                                                                                                           | DNS_NAME, VHOST                                             |
| wafw00f              | scan     | No              | Web Application Firewall Fingerprinting Tool                                                                                            | active, aggressive                                                                  | URL                                                                                                                           | WAF                                                         |
| wappalyzer           | scan     | No              | Extract technologies from web responses                                                                                                 | active, safe, web-basic, web-thorough                                               | HTTP_RESPONSE                                                                                                                 | TECHNOLOGY                                                  |
| affiliates           | scan     | No              | Summarize affiliate domains at the end of a scan                                                                                        | affiliates, passive, report, safe                                                   | *                                                                                                                             |                                                             |
| anubisdb             | scan     | No              | Query jldc.me's database for subdomains                                                                                                 | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| asn                  | scan     | No              | Query ripe and bgpview.io for ASNs                                                                                                      | passive, report, safe, subdomain-enum                                               | IP_ADDRESS                                                                                                                    | ASN                                                         |
| azure_realm          | scan     | No              | Retrieves the "AuthURL" from login.microsoftonline.com/getuserrealm                                                                     | affiliates, cloud-enum, passive, safe, subdomain-enum, web-basic                    | DNS_NAME                                                                                                                      | URL_UNVERIFIED                                              |
| azure_tenant         | scan     | No              | Query Azure for tenant sister domains                                                                                                   | affiliates, cloud-enum, passive, safe, subdomain-enum                               | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| bevigil              | scan     | Yes             | Retrieve OSINT data from mobile applications using BeVigil                                                                              | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME, URL_UNVERIFIED                                    |
| binaryedge           | scan     | Yes             | Query the BinaryEdge API                                                                                                                | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| bucket_file_enum     | scan     | No              | Works in conjunction with the filedownload module to download files from open storage buckets. Currently supported cloud providers: AWS | cloud-enum, passive, safe                                                           | STORAGE_BUCKET                                                                                                                | URL_UNVERIFIED                                              |
| builtwith            | scan     | Yes             | Query Builtwith.com for subdomains                                                                                                      | affiliates, passive, safe, subdomain-enum                                           | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| c99                  | scan     | Yes             | Query the C99 API for subdomains                                                                                                        | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| censys               | scan     | Yes             | Query the Censys API                                                                                                                    | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| certspotter          | scan     | No              | Query Certspotter's API for subdomains                                                                                                  | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| chaos                | scan     | Yes             | Query ProjectDiscovery's Chaos API for subdomains                                                                                       | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| columbus             | scan     | No              | Query the Columbus Project API for subdomains                                                                                           | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| credshed             | scan     | Yes             | Send queries to your own credshed server to check for known credentials of your targets                                                 | passive, safe                                                                       | DNS_NAME                                                                                                                      | EMAIL_ADDRESS, HASHED_PASSWORD, PASSWORD, USERNAME          |
| crobat               | scan     | No              | Query Project Crobat for subdomains                                                                                                     | passive, safe                                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| crt                  | scan     | No              | Query crt.sh (certificate transparency) for subdomains                                                                                  | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| dehashed             | scan     | Yes             | Execute queries against dehashed.com for exposed credentials                                                                            | email-enum, passive, safe                                                           | DNS_NAME                                                                                                                      | HASHED_PASSWORD, PASSWORD, USERNAME                         |
| digitorus            | scan     | No              | Query certificatedetails.com for subdomains                                                                                             | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| dnscommonsrv         | scan     | No              | Check for common SRV records                                                                                                            | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| dnsdumpster          | scan     | No              | Query dnsdumpster for subdomains                                                                                                        | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| emailformat          | scan     | No              | Query email-format.com for email addresses                                                                                              | email-enum, passive, safe                                                           | DNS_NAME                                                                                                                      | EMAIL_ADDRESS                                               |
| fullhunt             | scan     | Yes             | Query the fullhunt.io API for subdomains                                                                                                | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| github_codesearch    | scan     | Yes             | Query Github's API for code containing the target domain name                                                                           | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | CODE_REPOSITORY, URL_UNVERIFIED                             |
| github_org           | scan     | No              | Query Github's API for organization and member repositories                                                                             | passive, safe, subdomain-enum                                                       | ORG_STUB, SOCIAL                                                                                                              | CODE_REPOSITORY                                             |
| hackertarget         | scan     | No              | Query the hackertarget.com API for subdomains                                                                                           | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| hunterio             | scan     | Yes             | Query hunter.io for emails                                                                                                              | email-enum, passive, safe, subdomain-enum                                           | DNS_NAME                                                                                                                      | DNS_NAME, EMAIL_ADDRESS, URL_UNVERIFIED                     |
| internetdb           | scan     | No              | Query Shodan's InternetDB for open ports, hostnames, technologies, and vulnerabilities                                                  | passive, portscan, safe, subdomain-enum                                             | DNS_NAME, IP_ADDRESS                                                                                                          | DNS_NAME, FINDING, OPEN_TCP_PORT, TECHNOLOGY, VULNERABILITY |
| ip2location          | scan     | Yes             | Query IP2location.io's API for geolocation information.                                                                                 | passive, safe                                                                       | IP_ADDRESS                                                                                                                    | GEOLOCATION                                                 |
| ipneighbor           | scan     | No              | Look beside IPs in their surrounding subnet                                                                                             | aggressive, passive, subdomain-enum                                                 | IP_ADDRESS                                                                                                                    | IP_ADDRESS                                                  |
| ipstack              | scan     | Yes             | Query IPStack's GeoIP API                                                                                                               | passive, safe                                                                       | IP_ADDRESS                                                                                                                    | GEOLOCATION                                                 |
| leakix               | scan     | No              | Query leakix.net for subdomains                                                                                                         | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| massdns              | scan     | No              | Brute-force subdomains with massdns (highly effective)                                                                                  | aggressive, passive, subdomain-enum                                                 | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| myssl                | scan     | No              | Query myssl.com's API for subdomains                                                                                                    | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| nsec                 | scan     | No              | Enumerate subdomains by NSEC-walking                                                                                                    | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| otx                  | scan     | No              | Query otx.alienvault.com for subdomains                                                                                                 | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| passivetotal         | scan     | Yes             | Query the PassiveTotal API for subdomains                                                                                               | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| pgp                  | scan     | No              | Query common PGP servers for email addresses                                                                                            | email-enum, passive, safe                                                           | DNS_NAME                                                                                                                      | EMAIL_ADDRESS                                               |
| postman              | scan     | No              | Query Postman's API for related workspaces, collections, requests                                                                       | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | URL_UNVERIFIED                                              |
| rapiddns             | scan     | No              | Query rapiddns.io for subdomains                                                                                                        | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| riddler              | scan     | No              | Query riddler.io for subdomains                                                                                                         | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| securitytrails       | scan     | Yes             | Query the SecurityTrails API for subdomains                                                                                             | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| shodan_dns           | scan     | Yes             | Query Shodan for subdomains                                                                                                             | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| sitedossier          | scan     | No              | Query sitedossier.com for subdomains                                                                                                    | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| skymem               | scan     | No              | Query skymem.info for email addresses                                                                                                   | email-enum, passive, safe                                                           | DNS_NAME                                                                                                                      | EMAIL_ADDRESS                                               |
| social               | scan     | No              | Look for social media links in webpages                                                                                                 | passive, safe, social-enum                                                          | URL_UNVERIFIED                                                                                                                | SOCIAL                                                      |
| subdomaincenter      | scan     | No              | Query subdomain.center's API for subdomains                                                                                             | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| sublist3r            | scan     | No              | Query sublist3r's API for subdomains                                                                                                    | passive, safe                                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| threatminer          | scan     | No              | Query threatminer's API for subdomains                                                                                                  | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| urlscan              | scan     | No              | Query urlscan.io for subdomains                                                                                                         | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME, URL_UNVERIFIED                                    |
| viewdns              | scan     | No              | Query viewdns.info's reverse whois for related domains                                                                                  | affiliates, passive, safe                                                           | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| virustotal           | scan     | Yes             | Query VirusTotal's API for subdomains                                                                                                   | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| wayback              | scan     | No              | Query archive.org's API for subdomains                                                                                                  | passive, safe, subdomain-enum                                                       | DNS_NAME                                                                                                                      | DNS_NAME, URL_UNVERIFIED                                    |
| zoomeye              | scan     | Yes             | Query ZoomEye's API for subdomains                                                                                                      | affiliates, passive, safe, subdomain-enum                                           | DNS_NAME                                                                                                                      | DNS_NAME                                                    |
| asset_inventory      | output   | No              | Output to an asset inventory style flattened CSV file                                                                                   |                                                                                     | DNS_NAME, FINDING, IP_ADDRESS, OPEN_TCP_PORT, TECHNOLOGY, URL, VULNERABILITY                                                  | IP_ADDRESS, OPEN_TCP_PORT                                   |
| csv                  | output   | No              | Output to CSV                                                                                                                           |                                                                                     | *                                                                                                                             |                                                             |
| discord              | output   | No              | Message a Discord channel when certain events are encountered                                                                           |                                                                                     | *                                                                                                                             |                                                             |
| emails               | output   | No              | Output any email addresses found belonging to the target domain                                                                         | email-enum                                                                          | EMAIL_ADDRESS                                                                                                                 |                                                             |
| http                 | output   | No              | Send every event to a custom URL via a web request                                                                                      |                                                                                     | *                                                                                                                             |                                                             |
| human                | output   | No              | Output to text                                                                                                                          |                                                                                     | *                                                                                                                             |                                                             |
| json                 | output   | No              | Output to Newline-Delimited JSON (NDJSON)                                                                                               |                                                                                     | *                                                                                                                             |                                                             |
| neo4j                | output   | No              | Output to Neo4j                                                                                                                         |                                                                                     | *                                                                                                                             |                                                             |
| python               | output   | No              | Output via Python API                                                                                                                   |                                                                                     | *                                                                                                                             |                                                             |
| slack                | output   | No              | Message a Slack channel when certain events are encountered                                                                             |                                                                                     | *                                                                                                                             |                                                             |
| subdomains           | output   | No              | Output only resolved, in-scope subdomains                                                                                               | subdomain-enum                                                                      | DNS_NAME, DNS_NAME_UNRESOLVED                                                                                                 |                                                             |
| teams                | output   | No              | Message a Teams channel when certain events are encountered                                                                             |                                                                                     | *                                                                                                                             |                                                             |
| web_report           | output   | No              | Create a markdown report with web assets                                                                                                |                                                                                     | FINDING, TECHNOLOGY, URL, VHOST, VULNERABILITY                                                                                |                                                             |
| websocket            | output   | No              | Output to websockets                                                                                                                    |                                                                                     | *                                                                                                                             |                                                             |
| aggregate            | internal | No              | Summarize statistics at the end of a scan                                                                                               | passive, safe                                                                       |                                                                                                                               |                                                             |
| excavate             | internal | No              | Passively extract juicy tidbits from scan data                                                                                          | passive                                                                             | HTTP_RESPONSE                                                                                                                 | URL_UNVERIFIED                                              |
| speculate            | internal | No              | Derive certain event types from others by common sense                                                                                  | passive                                                                             | AZURE_TENANT, DNS_NAME, DNS_NAME_UNRESOLVED, HTTP_RESPONSE, IP_ADDRESS, IP_RANGE, SOCIAL, STORAGE_BUCKET, URL, URL_UNVERIFIED | DNS_NAME, FINDING, IP_ADDRESS, OPEN_TCP_PORT, ORG_STUB      |
<!-- END BBOT MODULES -->
