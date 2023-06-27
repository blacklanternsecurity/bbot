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

## Using BBOT as a Python library
**Synchronous**
~~~python
from bbot.scanner import Scanner

# any number of targets can be specified
scan = Scanner("example.com", "scanme.nmap.org", modules=["nmap", "sslcert"])
for event in scan.start():
    print(event.json())
~~~

**Asynchronous**
~~~python
from bbot.scanner import Scanner

async def main():
    scan = Scanner("example.com", "scanme.nmap.org", modules=["nmap", "sslcert"])
    async for event in scan.async_start():
        print(event.json())

import asyncio
asyncio.run(main())
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


# Usage
~~~
$ bbot --help
usage: bbot [-h] [--help-all] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]] [--strict-scope] [-m MODULE [MODULE ...]] [-l]
            [-em MODULE [MODULE ...]] [-f FLAG [FLAG ...]] [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]] [-om MODULE [MODULE ...]] [--allow-deadly] [-n SCAN_NAME] [-o DIR] [-c [CONFIG ...]]
            [-v] [-d] [-s] [--force] [-y] [--dry-run] [--current-config] [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps] [-a] [--version]

Bighuge BLS OSINT Tool

options:
  -h, --help            show this help message and exit
  --help-all            Display full help including module config options

Target:
  -t TARGET [TARGET ...], --targets TARGET [TARGET ...]
                        Targets to seed the scan
  -w WHITELIST [WHITELIST ...], --whitelist WHITELIST [WHITELIST ...]
                        What's considered in-scope (by default it's the same as --targets)
  -b BLACKLIST [BLACKLIST ...], --blacklist BLACKLIST [BLACKLIST ...]
                        Don't touch these things
  --strict-scope        Don't consider subdomains of target/whitelist to be in-scope

Modules:
  -m MODULE [MODULE ...], --modules MODULE [MODULE ...]
                        Modules to enable. Choices: affiliates,anubisdb,asn,azure_tenant,badsecrets,bevigil,binaryedge,bucket_aws,bucket_azure,bucket_digitalocean,bucket_firebase,bucket_gcp,builtwith,bypass403,c99,censys,certspotter,crobat,crt,dnscommonsrv,dnsdumpster,dnszonetransfer,emailformat,ffuf,ffuf_shortnames,fingerprintx,fullhunt,generic_ssrf,github,gowitness,hackertarget,host_header,httpx,hunt,hunterio,iis_shortnames,ipneighbor,ipstack,leakix,masscan,massdns,naabu,nmap,ntlm,nuclei,otx,paramminer_cookies,paramminer_getparams,paramminer_headers,passivetotal,pgp,rapiddns,riddler,robots,secretsdb,securitytrails,shodan_dns,skymem,smuggler,social,sslcert,subdomain_hijack,sublist3r,telerik,threatminer,url_manipulation,urlscan,vhost,viewdns,virustotal,wafw00f,wappalyzer,wayback,zoomeye
  -l, --list-modules    List available modules.
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: active,affiliates,aggressive,cloud-enum,deadly,email-enum,iis-shortnames,passive,portscan,report,safe,service-enum,slow,social-enum,subdomain-enum,subdomain-hijack,web-basic,web-paramminer,web-screenshots,web-thorough
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Only enable modules with these flags (e.g. -rf passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. -ef aggressive)
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: asset_inventory,csv,http,human,json,neo4j,python,web_report,websocket
  --allow-deadly        Enable the use of highly aggressive modules

Scan:
  -n SCAN_NAME, --name SCAN_NAME
                        Name of scan (default: random)
  -o DIR, --output-dir DIR
  -c [CONFIG ...], --config [CONFIG ...]
                        custom config file, or configuration options in key=value format: 'modules.shodan.api_key=1234'
  -v, --verbose         Be more verbose
  -d, --debug           Enable debugging
  -s, --silent          Be quiet
  --force               Run scan even if module setups fail
  -y, --yes             Skip scan confirmation prompt
  --dry-run             Abort before executing scan
  --current-config      Show current config in YAML format

Module dependencies:
  Control how modules install their dependencies

  --no-deps             Don't install module dependencies
  --force-deps          Force install all module dependencies
  --retry-deps          Try again to install failed module dependencies
  --ignore-failed-deps  Run modules even if they have failed dependencies
  --install-all-deps    Install dependencies for all modules

Agent:
  Report back to a central server

  -a, --agent-mode      Start in agent mode

Misc:
  --version             show BBOT version and exit
~~~


# BBOT Config
Additional config options (such as API keys, rate limits, user-agent, etc.) can be passed to BBOT via its YAML config. BBOT loads its config beginning from `~/.config/bbot`:

- `~/.config/bbot/bbot.yml` <-- Use this one as your main config
- `~/.config/bbot/secrets.yml` <-- Use this one for sensitive stuff like API keys
- command line (`--config`) <-- Use this to specify a custom `.yml` or override individual config options

These config files will be automatically created for you when you first run BBOT.

Command-line arguments take precedence over all others. You can give BBOT a custom config file with `--config myconf.yml`, or individual arguments like this: `--config http_proxy=http://127.0.0.1:8080 modules.shodan_dns.api_key=1234`. To display the full and current BBOT config, including any command-line arguments, use `bbot --current-config`.

Note that placing the following in `bbot.yml`:
```yaml
modules:
  shodan:
    api_key: deadbeef
```
Is the same as:
```bash
bbot --config modules.shodan.api_key=deadbeef
```

For explanations of config options, see `defaults.yml` or the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#yaml-config)


# Output
By default, BBOT saves its output in TXT, JSON, and CSV formats. You can enable other output modules with `--output-module`.
~~~bash
# tee to a file
bbot -f subdomain-enum -t evilcorp.com | tee evilcorp.txt

# output to JSON
bbot --output-module json -f subdomain-enum -t evilcorp.com | jq

# output asset inventory in current directory
bbot -o . --output-module asset_inventory -f subdomain-enum -t evilcorp.com
~~~
For every scan, BBOT generates a unique and mildly-entertaining name like `demonic_jimmy`. Output for that scan, including scan stats and any gowitness screenshots, etc., are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed. You can change the location of BBOT's output with `--output`, and you can also pick a custom scan name with `--name`.

If you reuse a scan name, it will append to its original output files and leverage the previous.

## Neo4j
Neo4j is the funnest (and prettiest) way to view and interact with BBOT data.

![neo4j](https://user-images.githubusercontent.com/20261699/182398274-729f3c48-c23c-4db0-8c2e-8b403c1bf790.png)

- You can get Neo4j up and running with a single docker command:
~~~bash
docker run -p 7687:7687 -p 7474:7474 -v "$(pwd)/data/:/data/" -e NEO4J_AUTH=neo4j/bbotislife neo4j
~~~
- After that, run bbot with `--output-modules neo4j`
~~~bash
bbot -f subdomain-enum -t evilcorp.com --output-modules neo4j
~~~
- Browse data at http://localhost:7474


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
