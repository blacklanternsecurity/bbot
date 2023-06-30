# BEE·bot
### OSINT automation for hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot) [![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

BBOT is a powerful and modular OSINT (Open Source Intelligence) framework designed to map the attack surface of an organization. With BBOT, you can execute the entire OSINT workflow with just a single command.

![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

BBOT is inspired by [Spiderfoot](https://github.com/smicallef/spiderfoot) but takes it to the next level with features like multi-target scans, lightning-fast asyncio performance, and NLP-powered subdomain mutations. It offers a wide range of functionality, including subdomain enumeration, port scanning, web screenshots, vulnerability scanning, and much more. BBOT has over 80 modules and counting.

Whether you're a pentester, security researcher, or bug bounty hunter, BBOT simplifies and automates the OSINT process so you can focus on the fun part: hacking!

https://github.com/blacklanternsecurity/bbot/assets/20261699/ebf2a81e-7530-4a9e-922d-4e62eb949f35

Visualization courtesy of [VivaGraphJS](https://github.com/blacklanternsecurity/bbot-vivagraphjs)

# Getting Started

## Installation ([pip](https://pypi.org/project/bbot/))
Note: installing in a virtualenv (e.g. via `pipx`) is recommended. If you need help with installation, please refer to the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#installation).
~~~bash
# Prerequisites:
# - Linux (Windows and macOS are *not* supported)
# - Python 3.9 or newer

# stable version
pip install bbot

# bleeding edge (dev branch)
pip install --pre bbot

bbot --help
~~~

## Example Commands
Note: Scan output, logs, etc. are saved to `~/.bbot`.
~~~bash
# subdomains
bbot -t evilcorp.com -f subdomain-enum

# subdomains (passive only)
bbot -t evilcorp.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t evilcorp.com -f subdomain-enum -m naabu gowitness -n my_scan -o .

# subdomains + basic web scan (wappalyzer, robots.txt, iis shortnames, etc.)
bbot -t evilcorp.com -f subdomain-enum web-basic

# subdomains + web spider (search for emails, etc.)
bbot -t evilcorp.com -f subdomain-enum -c web_spider_distance=2 web_spider_depth=2

# everything at once because yes
# subdomains + emails + cloud + port scan + non-intrusive web + web screenshots + nuclei
bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m naabu gowitness nuclei --allow-deadly

# list modules
bbot -l
~~~

## Targets

Targets seed a scan with initial data. You can specify an unlimited number of targets, either directly on the command line or in files (or both!). Targets can be any of the following:

- DNS_NAME (`evilcorp.com`)
- IP_ADDRESS (`1.2.3.4`)
- IP_RANGE (`1.2.3.0/24`)
- URL (`https://www.evilcorp.com`)
- EMAIL_ADDRESS (`bob@evilcorp.com`)

For example, the following scan is totally valid:

~~~bash
# multiple targets
bbot -t evilcorp.com evilcorp.co.uk http://www.evilcorp.cn 1.2.3.0/24 other_targets.txt
~~~

Visit the wiki for more [tips and tricks](https://github.com/blacklanternsecurity/bbot/wiki#tips-and-tricks).

## [Docker](https://hub.docker.com/r/blacklanternsecurity/bbot)
BBOT provides docker images, along with helper script `bbot-docker.sh` to persist your BBOT scan data.
~~~bash
# helper script
./bbot-docker.sh --help

# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help
~~~

# Acknowledgements

Thanks to all these amazing people for contributing to BBOT! :heart:

If you have an idea for a feature or run into bugs of any kind, please submit an issue or a PR. We welcome contributions!

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

See also: [Release History](https://github.com/blacklanternsecurity/bbot/wiki/Release-History)
