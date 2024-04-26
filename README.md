[![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)](https://github.com/blacklanternsecurity/bbot)

#### /ˈBEE·bot/ (noun): A recursive internet scanner for hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![DEF CON Demo Labs 2023](https://img.shields.io/badge/DEF%20CON%20Demo%20Labs-2023-FF8400.svg)](https://forum.defcon.org/node/246338) [![PyPi Downloads](https://static.pepy.tech/personalized-badge/bbot?right_color=orange&left_color=grey)](https://pepy.tech/project/bbot) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

https://github.com/blacklanternsecurity/bbot/assets/20261699/e539e89b-92ea-46fa-b893-9cde94eebf81

_A BBOT scan in real-time - visualization with [VivaGraphJS](https://github.com/blacklanternsecurity/bbot-vivagraphjs)_

## Installation

```bash
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot
```

_For more installation methods, including [Docker](https://hub.docker.com/r/blacklanternsecurity/bbot), see [Getting Started](https://www.blacklanternsecurity.com/bbot/)_

## What is BBOT?

### BBOT is...

## 1) A Subdomain Finder

Passive API sources plus a recursive DNS brute-force with target-specific subdomain mutations.

```bash
# find subdomains of evilcorp.com
bbot -t evilcorp.com -p subdomain-enum
```

<details>
<summary><b>subdomain-enum.yml</b></summary>

```yaml
description: Enumerate subdomains via APIs, brute-force

flags:
  - subdomain-enum

output_modules:
  - subdomains

config:
  modules:
    stdout:
      format: text
      # only output DNS_NAMEs to the console
      event_types:
        - DNS_NAME
      # only show in-scope subdomains
      in_scope_only: True
      # display the raw subdomains, nothing else
      event_fields:
        - data
      # automatically dedupe
      accept_dups: False
```

</details>

<details>
<summary><b>SEE: Comparison to Other Subdomain Enumeration Tools</b></summary>

BBOT consistently finds 20-50% more subdomains than other tools. The bigger the domain, the bigger the difference. To learn how this is possible, see [How It Works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

![subdomain-stats-ebay](https://github.com/blacklanternsecurity/bbot/assets/20261699/53e07e9f-50b6-4b70-9e83-297dbfbcb436)

</details>


## 2) A Web Spider

```bash
# crawl evilcorp.com, extracting emails and other goodies
bbot -t evilcorp.com -p spider
```

## 3) An Email Gatherer

```bash
# enumerate evilcorp.com email addresses
bbot -t evilcorp.com -p subdomain-enum spider email-enum
```

## 4) A Web Scanner

```bash
# run a light web scan against www.evilcorp.com
bbot -t www.evilcorp.com -p web-basic

# run a heavy web scan against www.evilcorp.com
bbot -t www.evilcorp.com -p web-thorough
```

## 5) ...And Much More

```bash
# everything everywhere all at once
bbot -t evilcorp.com -p kitchen-sink

# roughly equivalent to:
bbot -t evilcorp.com -p subdomain-enum cloud-enum code-enum email-enum spider web-basic paramminer dirbust-light web-screenshots
```

## 6) It's Also a Python Library

#### Synchronous
```python
from bbot.scanner import Scanner

scan = Scanner("evilcorp.com", presets=["subdomain-enum"])
for event in scan.start():
    print(event)
```

#### Asynchronous
```python
from bbot.scanner import Scanner

async def main():
    scan = Scanner("evilcorp.com", presets=["subdomain-enum"])
    async for event in scan.async_start():
        print(event.json())

import asyncio
asyncio.run(main())
```

<details>
<summary><b>SEE: This Nefarious Discord Bot</b></summary>

A [BBOT Discord Bot](https://www.blacklanternsecurity.com/bbot/dev/discord_bot/) that responds to the `/scan` command. Scan the internet from the comfort of your discord server!

![bbot-discord](https://github.com/blacklanternsecurity/bbot/assets/20261699/22b268a2-0dfd-4c2a-b7c5-548c0f2cc6f9)

## Feature Overview

BBOT (Bighuge BLS OSINT Tool) is a recursive internet scanner inspired by [Spiderfoot](https://github.com/smicallef/spiderfoot), but designed to be faster, more reliable, and friendlier to pentesters, bug bounty hunters, and developers.

Special features include:

- Support for Multiple Targets
- Web Screenshots
- Suite of Offensive Web Modules
- AI-powered Subdomain Mutations
- Native Output to Neo4j (and more)
- Python API + Developer Documentation

## Targets

BBOT accepts an unlimited number of targets via `-t`. You can specify targets either directly on the command line or in files (or both!):

```bash
bbot -t evilcorp.com evilcorp.org 1.2.3.0/24 -f subdomain-enum
```

Targets can be any of the following:

- `DNS_NAME` (`evilcorp.com`)
- `IP_ADDRESS` (`1.2.3.4`)
- `IP_RANGE` (`1.2.3.0/24`)
- `OPEN_TCP_PORT` (`192.168.0.1:80`)
- `URL` (`https://www.evilcorp.com`)

For more information, see [Targets](https://www.blacklanternsecurity.com/bbot/scanning/#targets-t). To learn how BBOT handles scope, see [Scope](https://www.blacklanternsecurity.com/bbot/scanning/#scope).

## API Keys

Similar to Amass or Subfinder, BBOT supports API keys for various third-party services such as SecurityTrails, etc.

The standard way to do this is to enter your API keys in **`~/.config/bbot/bbot.yml`**:
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

## Documentation

<!-- BBOT DOCS TOC -->
- **User Manual**
    - **Basics**
        - [Getting Started](https://www.blacklanternsecurity.com/bbot/)
        - [How it Works](https://www.blacklanternsecurity.com/bbot/how_it_works)
        - [Comparison to Other Tools](https://www.blacklanternsecurity.com/bbot/comparison)
    - **Scanning**
        - [Scanning Overview](https://www.blacklanternsecurity.com/bbot/scanning/)
        - **Presets**
            - [Overview](https://www.blacklanternsecurity.com/bbot/scanning/presets)
            - [List of Presets](https://www.blacklanternsecurity.com/bbot/scanning/presets_list)
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

## Contribution

Some of the best BBOT modules were written by the community. BBOT is being constantly improved; every day it grows more powerful!

We welcome contributions. Not just code, but ideas too! If you have an idea for a new feature, please let us know in [Discussions](https://github.com/blacklanternsecurity/bbot/discussions). If you want to get your hands dirty, see [Contribution](https://www.blacklanternsecurity.com/bbot/contribution/). There you can find setup instructions and a simple tutorial on how to write a BBOT module. We also have extensive [Developer Documentation](https://www.blacklanternsecurity.com/bbot/dev/).

Thanks to these amazing people for contributing to BBOT! :heart:

<p align="center">
<a href="https://github.com/blacklanternsecurity/bbot/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=blacklanternsecurity/bbot&max=500">
</a>
</p>

Special thanks to:

- @TheTechromancer for creating [BBOT](https://github.com/blacklanternsecurity/bbot)
- @liquidsec for his extensive work on BBOT's web hacking features, including [badsecrets](https://github.com/blacklanternsecurity/badsecrets) and [baddns](https://github.com/blacklanternsecurity/baddns)
- Steve Micallef (@smicallef) for creating Spiderfoot
- @kerrymilan for his Neo4j and Ansible expertise
- @domwhewell-sage for his family of badass code-looting modules
- @aconite33 and @amiremami for their ruthless testing
- Aleksei Kornev (@alekseiko) for allowing us ownership of the bbot Pypi repository <3
