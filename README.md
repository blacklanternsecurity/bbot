# BEE·bot

### OSINT automation for hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Pypi Downloads](https://img.shields.io/pypi/dm/bbot)](https://pypi.org/project/bbot) [![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

BBOT is a modular, recursive OSINT framework that can execute the entire OSINT workflow in a single command.

![bbot_banner](https://github.com/blacklanternsecurity/bbot/assets/20261699/af2e822c-d7d6-40e7-bcba-2ce52faa6c4c)

BBOT is inspired by [Spiderfoot](https://github.com/smicallef/spiderfoot) but takes it to the next level with features like multi-target scans, lightning-fast asyncio performance, and NLP-powered subdomain mutations. It offers a wide range of functionality, including subdomain enumeration, port scanning, web screenshots, vulnerability scanning, and much more. 

![subdomain-stats-boeing](https://github.com/blacklanternsecurity/bbot/assets/20261699/de0154c1-476e-4337-9599-45a1c5e0e78b)

BBOT typically outperforms other subdomain enumeration tools by 20-25%. To learn how this is possible, see [How It Works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

## Consider checking out our [Documentation](https://www.blacklanternsecurity.com/bbot):

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
    - [List of Modules](https://www.blacklanternsecurity.com/bbot/scanning/list_of_modules)
- **Contribution**
    - [How to Write a Module](https://www.blacklanternsecurity.com/bbot/contribution)
- **Misc**
    - [Release History](https://www.blacklanternsecurity.com/bbot/release_history)
    - [Troubleshooting](https://www.blacklanternsecurity.com/bbot/troubleshooting)
<!-- END BBOT DOCS TOC -->

## Installation ([pip](https://pypi.org/project/bbot/))

For more installation methods including [Docker](https://hub.docker.com/r/blacklanternsecurity/bbot), see [Installation](https://www.blacklanternsecurity.com/bbot/#installation).

```bash
# Prerequisites:
# - Linux (Windows and macOS are *not* supported)
# - Python 3.9 or newer

# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot

bbot --help
```

## Example Commands

Scan output, logs, etc. are saved to `~/.bbot`. For more detailed examples and explanations, see [Scanning](https://www.blacklanternsecurity.com/scanning).

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

BBOT accepts an unlimited number of targets which you can specify either directly on the command line or in files (or both!). Targets can be any of the following:

- DNS_NAME (`evilcorp.com`)
- IP_ADDRESS (`1.2.3.4`)
- IP_RANGE (`1.2.3.0/24`)
- URL (`https://www.evilcorp.com`)

For more information, see [Targets](https://www.blacklanternsecurity.com/scanning/#targets-t). To learn how BBOT handles scope, see [Scope](https://www.blacklanternsecurity.com/scanning/#scope).

## BBOT as a Python library

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

## Acknowledgements

Thanks to these amazing people for contributing to BBOT! :heart:

If you're interested in contributing to BBOT, or just curious how it works under the hood, see [Contribution](https://www.blacklanternsecurity.com/bbot/contribution/).

<p align="center">
<a href="https://github.com/blacklanternsecurity/bbot/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=blacklanternsecurity/bbot&max=500">
</a>
</p>

Special thanks to the following people who made BBOT possible:

- @TheTechromancer for creating BBOT
- @liquidsec for his extensive work on BBOT's web hacking features
- Steve Micallef (@smicallef) for creating Spiderfoot
- @kerrymilan for his Neo4j and Ansible expertise
- Aleksei Kornev (@alekseiko) for allowing us ownership of the bbot Pypi repository <3
