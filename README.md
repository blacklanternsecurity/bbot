[![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)](https://github.com/blacklanternsecurity/bbot)

# BEE·bot

### A Recursive Internet Scanner for Hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![DEF CON Demo Labs 2023](https://img.shields.io/badge/DEF%20CON%20Demo%20Labs-2023-FF8400.svg)](https://forum.defcon.org/node/246338) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Pypi Downloads](https://img.shields.io/pypi/dm/bbot)](https://pypistats.org/packages/bbot) [![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

BBOT (Bighuge BLS OSINT Tool) is a recursive internet scanner inspired by [Spiderfoot](https://github.com/smicallef/spiderfoot), but designed to be faster, more reliable, and friendlier to pentesters, bug bounty hunters, and developers.

Special features include:

- Support for Multiple Targets
- Web Screenshots
- Suite of Offensive Web Modules
- AI-powered Subdomain Mutations
- Native Output to Neo4j (and more)
- Python API + Developer Documentation

https://github.com/blacklanternsecurity/bbot/assets/20261699/742df3fe-5d1f-4aea-83f6-f990657bf695

_A BBOT scan in real-time - visualization with [VivaGraphJS](https://github.com/blacklanternsecurity/bbot-vivagraphjs)_

## Quick Start Guide

Below are some short help sections to get you up and running.

<details>
<summary><b>Installation ( Pip )</b></summary>

Note: BBOT's [PyPi package](https://pypi.org/project/bbot/) requires Linux and Python 3.9+.

```bash
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot

bbot --help
```

</details>

<details>
<summary><b>Installation ( Docker )</b></summary>

[Docker images](https://hub.docker.com/r/blacklanternsecurity/bbot) are provided, along with helper script `bbot-docker.sh` to persist your scan data.

```bash
# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help

# helper script
git clone https://github.com/blacklanternsecurity/bbot && cd bbot
./bbot-docker.sh --help
```

</details>

<details>
<summary><b>Usage</b></summary>

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

## BBOT as a Python Library

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

</details>

<details>
<summary><b>Documentation - Table of Contents</b></summary>

<!-- BBOT DOCS TOC -->
- **User Manual**
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
    - **Misc**
        - [Release History](https://www.blacklanternsecurity.com/bbot/release_history)
        - [Troubleshooting](https://www.blacklanternsecurity.com/bbot/troubleshooting)
- **Developer Manual**
    - [How to Write a Module](https://www.blacklanternsecurity.com/bbot/contribution)
    - [Development Overview](https://www.blacklanternsecurity.com/bbot/dev/)
    - [Scanner](https://www.blacklanternsecurity.com/bbot/dev/scanner)
    - [Event](https://www.blacklanternsecurity.com/bbot/dev/event)
    - [Target](https://www.blacklanternsecurity.com/bbot/dev/target)
    - [BaseModule](https://www.blacklanternsecurity.com/bbot/dev/basemodule)
    - **Helpers**
        - [Overview](https://www.blacklanternsecurity.com/bbot/dev/helpers/)
        - [Command](https://www.blacklanternsecurity.com/bbot/dev/helpers/command)
        - [DNS](https://www.blacklanternsecurity.com/bbot/dev/helpers/dns)
        - [Interactsh](https://www.blacklanternsecurity.com/bbot/dev/helpers/interactsh)
        - [Miscellaneous](https://www.blacklanternsecurity.com/bbot/dev/helpers/misc)
        - [Web](https://www.blacklanternsecurity.com/bbot/dev/helpers/web)
        - [Word Cloud](https://www.blacklanternsecurity.com/bbot/dev/helpers/wordcloud)
<!-- END BBOT DOCS TOC -->

</details>

<details>
<summary><b>Contribution</b></summary>

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

</details>

## Comparison to Other Tools

BBOT consistently finds 20-50% more subdomains than other tools. The bigger the domain, the bigger the difference. To learn how this is possible, see [How It Works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

![subdomain-stats-ebay](https://github.com/blacklanternsecurity/bbot/assets/20261699/53e07e9f-50b6-4b70-9e83-297dbfbcb436)

## BBOT Modules By Flag
For a full list of modules, including the data types consumed and emitted by each one, see [List of Modules](https://www.blacklanternsecurity.com/bbot/modules/list_of_modules/).

<!-- BBOT MODULE FLAGS -->
| Flag             | # Modules   | Description                                   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|------------------|-------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| safe             | 76          | Non-intrusive, safe to run                    | affiliates, aggregate, ajaxpro, anubisdb, asn, azure_realm, azure_tenant, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, credshed, crobat, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, dnszonetransfer, emailformat, filedownload, fingerprintx, fullhunt, git, github_codesearch, github_org, gowitness, hackertarget, httpx, hunt, hunterio, iis_shortnames, internetdb, ip2location, ipstack, leakix, myssl, newsletters, nsec, ntlm, oauth, otx, passivetotal, pgp, postman, rapiddns, riddler, robots, secretsdb, securitytrails, shodan_dns, sitedossier, skymem, social, sslcert, subdomain_hijack, subdomaincenter, sublist3r, threatminer, urlscan, viewdns, virustotal, wappalyzer, wayback, zoomeye |
| passive          | 57          | Never connects to target systems              | affiliates, aggregate, anubisdb, asn, azure_realm, azure_tenant, bevigil, binaryedge, bucket_file_enum, builtwith, c99, censys, certspotter, chaos, columbus, credshed, crobat, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, emailformat, excavate, fullhunt, github_codesearch, github_org, hackertarget, hunterio, internetdb, ip2location, ipneighbor, ipstack, leakix, massdns, myssl, nsec, otx, passivetotal, pgp, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, skymem, social, speculate, subdomaincenter, sublist3r, threatminer, urlscan, viewdns, virustotal, wayback, zoomeye                                                                                                                                                                                                                                            |
| subdomain-enum   | 47          | Enumerates subdomains                         | anubisdb, asn, azure_realm, azure_tenant, bevigil, binaryedge, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, dnszonetransfer, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, nsec, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, sslcert, subdomain_hijack, subdomaincenter, subdomains, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                            |
| active           | 40          | Makes active connections to target systems    | ajaxpro, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dnszonetransfer, ffuf, ffuf_shortnames, filedownload, fingerprintx, generic_ssrf, git, gowitness, host_header, httpx, hunt, iis_shortnames, masscan, newsletters, nmap, ntlm, nuclei, oauth, paramminer_cookies, paramminer_getparams, paramminer_headers, robots, secretsdb, smuggler, sslcert, subdomain_hijack, telerik, url_manipulation, vhost, wafw00f, wappalyzer                                                                                                                                                                                                                                                                                                                                                               |
| web-thorough     | 29          | More advanced web scanning functionality      | ajaxpro, azure_realm, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, ffuf_shortnames, filedownload, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, nmap, ntlm, oauth, robots, secretsdb, smuggler, sslcert, subdomain_hijack, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| aggressive       | 19          | Generates a large amount of network traffic   | bypass403, dastardly, ffuf, ffuf_shortnames, generic_ssrf, host_header, ipneighbor, masscan, massdns, nmap, nuclei, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, telerik, url_manipulation, vhost, wafw00f                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| web-basic        | 17          | Basic, non-intrusive web scan functionality   | azure_realm, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, secretsdb, sslcert, subdomain_hijack, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| cloud-enum       | 11          | Enumerates cloud resources                    | azure_realm, azure_tenant, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, httpx, oauth, subdomain_hijack                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| affiliates       | 8           | Discovers affiliated hostnames/domains        | affiliates, azure_realm, azure_tenant, builtwith, oauth, sslcert, viewdns, zoomeye                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| slow             | 8           | May take a long time to complete              | bucket_digitalocean, dastardly, fingerprintx, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| email-enum       | 7           | Enumerates email addresses                    | dehashed, emailformat, emails, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| deadly           | 4           | Highly aggressive                             | dastardly, ffuf, nuclei, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| portscan         | 3           | Discovers open ports                          | internetdb, masscan, nmap                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| web-paramminer   | 3           | Discovers HTTP parameters through brute-force | paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| iis-shortnames   | 2           | Scans for IIS Shortname vulnerability         | ffuf_shortnames, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| report           | 2           | Generates a report at the end of the scan     | affiliates, asn                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| social-enum      | 2           | Enumerates social media                       | httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| service-enum     | 1           | Identifies protocols running on open ports    | fingerprintx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| subdomain-hijack | 1           | Detects hijackable subdomains                 | subdomain_hijack                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| web-screenshots  | 1           | Takes screenshots of web pages                | gowitness                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
<!-- END BBOT MODULE FLAGS -->
</details>
