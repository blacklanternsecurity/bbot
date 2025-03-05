[![bbot_banner](https://github.com/user-attachments/assets/f02804ce-9478-4f1e-ac4d-9cf5620a3214)](https://github.com/blacklanternsecurity/bbot)

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![DEF CON Recon Village 2024](https://img.shields.io/badge/DEF%20CON%20Demo%20Labs-2023-FF8400.svg)](https://www.reconvillage.org/talks) [![PyPi Downloads](https://static.pepy.tech/personalized-badge/bbot?right_color=orange&left_color=grey)](https://pepy.tech/project/bbot) [![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

### **BEE·bot** is a multipurpose scanner inspired by [Spiderfoot](https://github.com/smicallef/spiderfoot), built to automate your **Recon**, **Bug Bounties**, and **ASM**!

https://github.com/blacklanternsecurity/bbot/assets/20261699/e539e89b-92ea-46fa-b893-9cde94eebf81

_A BBOT scan in real-time - visualization with [VivaGraphJS](https://github.com/blacklanternsecurity/bbot-vivagraphjs)_

## Installation

```bash
# stable version
pipx install bbot

# bleeding edge (dev branch)
pipx install --pip-args '\--pre' bbot
```

_For more installation methods, including [Docker](https://hub.docker.com/r/blacklanternsecurity/bbot), see [Getting Started](https://www.blacklanternsecurity.com/bbot/Stable/)_

## Example Commands

### 1) Subdomain Finder

Passive API sources plus a recursive DNS brute-force with target-specific subdomain mutations.

```bash
# find subdomains of evilcorp.com
bbot -t evilcorp.com -p subdomain-enum

# passive sources only
bbot -t evilcorp.com -p subdomain-enum -rf passive
```

<!-- BBOT SUBDOMAIN-ENUM PRESET EXPANDABLE -->

<details>
<summary><b><code>subdomain-enum.yml</code></b></summary>

```yaml
description: Enumerate subdomains via APIs, brute-force

flags:
  # enable every module with the subdomain-enum flag
  - subdomain-enum

output_modules:
  # output unique subdomains to TXT file
  - subdomains

config:
  dns:
    threads: 25
    brute_threads: 1000
  # put your API keys here
  # modules:
  #   github:
  #     api_key: ""
  #   chaos:
  #     api_key: ""
  #   securitytrails:
  #     api_key: ""

```

</details>

<!-- END BBOT SUBDOMAIN-ENUM PRESET EXPANDABLE -->

BBOT consistently finds 20-50% more subdomains than other tools. The bigger the domain, the bigger the difference. To learn how this is possible, see [How It Works](https://www.blacklanternsecurity.com/bbot/Dev/how_it_works/).

![subdomain-stats-ebay](https://github.com/blacklanternsecurity/bbot/assets/20261699/de3e7f21-6f52-4ac4-8eab-367296cd385f)

### 2) Web Spider

```bash
# crawl evilcorp.com, extracting emails and other goodies
bbot -t evilcorp.com -p spider
```

<!-- BBOT SPIDER PRESET EXPANDABLE -->

<details>
<summary><b><code>spider.yml</code></b></summary>

```yaml
description: Recursive web spider

modules:
  - httpx

blacklist:
  # Prevent spider from invalidating sessions by logging out
  - "RE:/.*(sign|log)[_-]?out"

config:
  web:
    # how many links to follow in a row
    spider_distance: 2
    # don't follow links whose directory depth is higher than 4
    spider_depth: 4
    # maximum number of links to follow per page
    spider_links_per_page: 25

```

</details>

<!-- END BBOT SPIDER PRESET EXPANDABLE -->

### 3) Email Gatherer

```bash
# quick email enum with free APIs + scraping
bbot -t evilcorp.com -p email-enum

# pair with subdomain enum + web spider for maximum yield
bbot -t evilcorp.com -p email-enum subdomain-enum spider
```

<!-- BBOT EMAIL-ENUM PRESET EXPANDABLE -->

<details>
<summary><b><code>email-enum.yml</code></b></summary>

```yaml
description: Enumerate email addresses from APIs, web crawling, etc.

flags:
  - email-enum

output_modules:
  - emails

```

</details>

<!-- END BBOT EMAIL-ENUM PRESET EXPANDABLE -->

### 4) Web Scanner

```bash
# run a light web scan against www.evilcorp.com
bbot -t www.evilcorp.com -p web-basic

# run a heavy web scan against www.evilcorp.com
bbot -t www.evilcorp.com -p web-thorough
```

<!-- BBOT WEB-BASIC PRESET EXPANDABLE -->

<details>
<summary><b><code>web-basic.yml</code></b></summary>

```yaml
description: Quick web scan

include:
  - iis-shortnames

flags:
  - web-basic

```

</details>

<!-- END BBOT WEB-BASIC PRESET EXPANDABLE -->

<!-- BBOT WEB-THOROUGH PRESET EXPANDABLE -->

<details>
<summary><b><code>web-thorough.yml</code></b></summary>

```yaml
description: Aggressive web scan

include:
  # include the web-basic preset
  - web-basic

flags:
  - web-thorough

```

</details>

<!-- END BBOT WEB-THOROUGH PRESET EXPANDABLE -->

### 5) Everything Everywhere All at Once

```bash
# everything everywhere all at once
bbot -t evilcorp.com -p kitchen-sink --allow-deadly

# roughly equivalent to:
bbot -t evilcorp.com -p subdomain-enum cloud-enum code-enum email-enum spider web-basic paramminer dirbust-light web-screenshots --allow-deadly
```

<!-- BBOT KITCHEN-SINK PRESET EXPANDABLE -->

<details>
<summary><b><code>kitchen-sink.yml</code></b></summary>

```yaml
description: Everything everywhere all at once

include:
  - subdomain-enum
  - cloud-enum
  - code-enum
  - email-enum
  - spider
  - web-basic
  - paramminer
  - dirbust-light
  - web-screenshots
  - baddns-intense

config:
  modules:
    baddns:
      enable_references: True

```

</details>

<!-- END BBOT KITCHEN-SINK PRESET EXPANDABLE -->

## How it Works

Click the graph below to explore the [inner workings](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/) of BBOT.

[![image](https://github.com/blacklanternsecurity/bbot/assets/20261699/e55ba6bd-6d97-48a6-96f0-e122acc23513)](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works/)

## Output Modules

- [Neo4j](docs/scanning/output.md#neo4j)
- [Teams](docs/scanning/output.md#teams)
- [Discord](docs/scanning/output.md#discord)
- [Slack](docs/scanning/output.md#slack)
- [Postgres](docs/scanning/output.md#postgres)
- [MySQL](docs/scanning/output.md#mysql)
- [SQLite](docs/scanning/output.md#sqlite)
- [Splunk](docs/scanning/output.md#splunk)
- [Elasticsearch](docs/scanning/output.md#elasticsearch)
- [CSV](docs/scanning/output.md#csv)
- [JSON](docs/scanning/output.md#json)
- [HTTP](docs/scanning/output.md#http)
- [Websocket](docs/scanning/output.md#websocket)

...and [more](docs/scanning/output.md)!

## BBOT as a Python Library

#### Synchronous
```python
from bbot.scanner import Scanner

if __name__ == "__main__":
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

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

<details>
<summary><b>SEE: This Nefarious Discord Bot</b></summary>

A [BBOT Discord Bot](https://www.blacklanternsecurity.com/bbot/Stable/dev/#discord-bot-example) that responds to the `/scan` command. Scan the internet from the comfort of your discord server!

![bbot-discord](https://github.com/blacklanternsecurity/bbot/assets/20261699/22b268a2-0dfd-4c2a-b7c5-548c0f2cc6f9)

</details>

## Feature Overview

- Support for Multiple Targets
- Web Screenshots
- Suite of Offensive Web Modules
- NLP-powered Subdomain Mutations
- Native Output to Neo4j (and more)
- Automatic dependency install with Ansible
- Search entire attack surface with custom YARA rules
- Python API + Developer Documentation

## Targets

BBOT accepts an unlimited number of targets via `-t`. You can specify targets either directly on the command line or in files (or both!):

```bash
bbot -t evilcorp.com evilcorp.org 1.2.3.0/24 -p subdomain-enum
```

Targets can be any of the following:

- DNS Name (`evilcorp.com`)
- IP Address (`1.2.3.4`)
- IP Range (`1.2.3.0/24`)
- Open TCP Port (`192.168.0.1:80`)
- URL (`https://www.evilcorp.com`)
- Email Address (`bob@evilcorp.com`)
- Organization (`ORG:evilcorp`)
- Username (`USER:bobsmith`)
- Filesystem (`FILESYSTEM:/tmp/asdf`)
- Mobile App (`MOBILE_APP:https://play.google.com/store/apps/details?id=com.evilcorp.app`)

For more information, see [Targets](https://www.blacklanternsecurity.com/bbot/Stable/scanning/#targets-t). To learn how BBOT handles scope, see [Scope](https://www.blacklanternsecurity.com/bbot/Stable/scanning/#scope).

## API Keys

Similar to Amass or Subfinder, BBOT supports API keys for various third-party services such as SecurityTrails, etc.

The standard way to do this is to enter your API keys in **`~/.config/bbot/bbot.yml`**. Note that multiple API keys are allowed:
```yaml
modules:
  shodan_dns:
    api_key: 4f41243847da693a4f356c0486114bc6
  c99:
    # multiple API keys
    api_key:
      - 21a270d5f59c9b05813a72bb41707266
      - ea8f243d9885cf8ce9876a580224fd3c
      - 5bc6ed268ab6488270e496d3183a1a27
  virustotal:
    api_key: dd5f0eee2e4a99b71a939bded450b246
  securitytrails:
    api_key: d9a05c3fd9a514497713c54b4455d0b0
```

If you like, you can also specify them on the command line:
```bash
bbot -c modules.virustotal.api_key=dd5f0eee2e4a99b71a939bded450b246
```

For details, see [Configuration](https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration/).

## Complete Lists of Modules, Flags, etc.

- Complete list of [Modules](https://www.blacklanternsecurity.com/bbot/Stable/modules/list_of_modules/).
- Complete list of [Flags](https://www.blacklanternsecurity.com/bbot/Stable/scanning/#list-of-flags).
- Complete list of [Presets](https://www.blacklanternsecurity.com/bbot/Stable/scanning/presets_list/).
    - Complete list of [Global Config Options](https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration/#global-config-options).
    - Complete list of [Module Config Options](https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration/#module-config-options).

## Documentation

<!-- BBOT DOCS TOC -->
- **User Manual**
    - **Basics**
        - [Getting Started](https://www.blacklanternsecurity.com/bbot/Stable/)
        - [How it Works](https://www.blacklanternsecurity.com/bbot/Stable/how_it_works)
        - [Comparison to Other Tools](https://www.blacklanternsecurity.com/bbot/Stable/comparison)
    - **Scanning**
        - [Scanning Overview](https://www.blacklanternsecurity.com/bbot/Stable/scanning/)
        - **Presets**
            - [Overview](https://www.blacklanternsecurity.com/bbot/Stable/scanning/presets)
            - [List of Presets](https://www.blacklanternsecurity.com/bbot/Stable/scanning/presets_list)
        - [Events](https://www.blacklanternsecurity.com/bbot/Stable/scanning/events)
        - [Output](https://www.blacklanternsecurity.com/bbot/Stable/scanning/output)
        - [Tips and Tricks](https://www.blacklanternsecurity.com/bbot/Stable/scanning/tips_and_tricks)
        - [Advanced Usage](https://www.blacklanternsecurity.com/bbot/Stable/scanning/advanced)
        - [Configuration](https://www.blacklanternsecurity.com/bbot/Stable/scanning/configuration)
    - **Modules**
        - [List of Modules](https://www.blacklanternsecurity.com/bbot/Stable/modules/list_of_modules)
        - [Nuclei](https://www.blacklanternsecurity.com/bbot/Stable/modules/nuclei)
        - [Custom YARA Rules](https://www.blacklanternsecurity.com/bbot/Stable/modules/custom_yara_rules)
    - **Misc**
        - [Contribution](https://www.blacklanternsecurity.com/bbot/Stable/contribution)
        - [Release History](https://www.blacklanternsecurity.com/bbot/Stable/release_history)
        - [Troubleshooting](https://www.blacklanternsecurity.com/bbot/Stable/troubleshooting)
- **Developer Manual**
    - [Development Overview](https://www.blacklanternsecurity.com/bbot/Stable/dev/)
    - [Setting Up a Dev Environment](https://www.blacklanternsecurity.com/bbot/Stable/dev/dev_environment)
    - [BBOT Internal Architecture](https://www.blacklanternsecurity.com/bbot/Stable/dev/architecture)
    - [How to Write a BBOT Module](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto)
    - [Unit Tests](https://www.blacklanternsecurity.com/bbot/Stable/dev/tests)
    - [Discord Bot Example](https://www.blacklanternsecurity.com/bbot/Stable/dev/discord_bot)
    - **Code Reference**
        - [Scanner](https://www.blacklanternsecurity.com/bbot/Stable/dev/scanner)
        - [Presets](https://www.blacklanternsecurity.com/bbot/Stable/dev/presets)
        - [Event](https://www.blacklanternsecurity.com/bbot/Stable/dev/event)
        - [Target](https://www.blacklanternsecurity.com/bbot/Stable/dev/target)
        - [BaseModule](https://www.blacklanternsecurity.com/bbot/Stable/dev/basemodule)
        - [BBOTCore](https://www.blacklanternsecurity.com/bbot/Stable/dev/core)
        - [Engine](https://www.blacklanternsecurity.com/bbot/Stable/dev/engine)
        - **Helpers**
            - [Overview](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/)
            - [Command](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/command)
            - [DNS](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/dns)
            - [Interactsh](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/interactsh)
            - [Miscellaneous](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/misc)
            - [Web](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/web)
            - [Word Cloud](https://www.blacklanternsecurity.com/bbot/Stable/dev/helpers/wordcloud)
<!-- END BBOT DOCS TOC -->

## Contribution

Some of the best BBOT modules were written by the community. BBOT is being constantly improved; every day it grows more powerful!

We welcome contributions. Not just code, but ideas too! If you have an idea for a new feature, please let us know in [Discussions](https://github.com/blacklanternsecurity/bbot/discussions). If you want to get your hands dirty, see [Contribution](https://www.blacklanternsecurity.com/bbot/Stable/contribution/). There you can find setup instructions and a simple tutorial on how to write a BBOT module. We also have extensive [Developer Documentation](https://www.blacklanternsecurity.com/bbot/Stable/dev/).

Thanks to these amazing people for contributing to BBOT! :heart:

<p align="center">
<a href="https://github.com/blacklanternsecurity/bbot/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=blacklanternsecurity/bbot&max=500">
</a>
</p>

Special thanks to:

- @TheTechromancer for creating BBOT
- @liquidsec for his extensive work on BBOT's web hacking features, including [badsecrets](https://github.com/blacklanternsecurity/badsecrets) and [baddns](https://github.com/blacklanternsecurity/baddns)
- Steve Micallef (@smicallef) for creating Spiderfoot
- @kerrymilan for his Neo4j and Ansible expertise
- @domwhewell-sage for his family of badass code-looting modules
- @aconite33 and @amiremami for their ruthless testing
- Aleksei Kornev (@alekseiko) for granting us ownership of the bbot Pypi repository <3
