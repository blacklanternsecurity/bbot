![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

# BEE·bot
### OSINT automation for hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot)

![subdomain demo](https://user-images.githubusercontent.com/20261699/182274919-d4f5aa69-993a-40aa-95d5-f5e69e96026c.gif)

### **BBOT** is a **recursive**, **modular** OSINT framework written in Python.

It is capable of executing the entire OSINT process in a single command, including subdomain enumeration, port scanning, web screenshots (with its `gowitness` module), vulnerability scanning (with `nuclei`), and much more.

BBOT currently has over **50 modules** and counting.

## Installation
~~~bash
pipx install bbot
~~~
Prerequisites: 
- Python 3.9 or newer MUST be installed
- `pipx` is recommended as an alternative to `pip` because it installs BBOT in its own Python environment.

If you need help with installation, please refer to the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#installation).

## Scanning with BBOT

#### Note: the `httpx` module is recommended in most scans because it is used by BBOT to visit webpages. For details, see the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#note-on-the-httpx-module).

### Examples
~~~bash
# list modules
bbot -l

# subdomain enumeration
bbot --flags subdomain-enum --modules naabu httpx --targets evilcorp.com

# passive modules only
bbot --flags passive --targets evilcorp.com

# web screenshots with gowitness
bbot -m naabu httpx gowitness --name my_scan --output-dir . -t evilcorp.com 1.2.3.4/28 4.3.2.1 targets.txt

# web spider (search for emails, etc.)
bbot -m httpx -c web_spider_distance=2 web_spider_depth=2 -t www.evilcorp.com
~~~

## Using BBOT as a Python library
~~~python
from bbot.scanner import Scanner

scan = Scanner("evilcorp.com", "1.2.3.0/24", modules=["naabu"], output_modules=["json"])
scan.start()
~~~

# Output
BBOT can output to TXT, JSON, CSV, Neo4j, and more with `--output-module`. You can output to multiple formats simultaneously.
~~~bash
# tee to a file
bbot -f subdomain-enum -t evilcorp.com | tee evilcorp.txt

# output to JSON
bbot --output-module json -f subdomain-enum -t evilcorp.com | jq

# output to CSV, TXT, and JSON, in current directory
bbot -o . --output-module human csv json -f subdomain-enum -t evilcorp.com
~~~
For every scan, BBOT generates a unique and mildly-entertaining name like `fuzzy_gandalf`. Output for that scan, including the word cloud and any gowitness screenshots, etc., are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed. You can change the location of BBOT's output with `--output`, and you can also pick a custom scan name with `--name`.

If you reuse a scan name, it will append to its original output files and leverage the previous word cloud.

# Neo4j
Neo4j is the funnest (and prettiest) way to view and interact with BBOT data.

![neo4j](https://user-images.githubusercontent.com/20261699/182398274-729f3c48-c23c-4db0-8c2e-8b403c1bf790.png)

- You can get Neo4j up and running with a single docker command:
~~~bash
docker run -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bbotislife neo4j
~~~
- After that, run bbot with `--output-modules neo4j`
~~~bash
bbot -f subdomain-enum -t evilcorp.com --output-modules human neo4j
~~~
- Browse data at http://localhost:7474

# Usage
~~~
$ bbot --help
usage: bbot [-h] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]] [-s] [-n SCAN_NAME] [-m MODULE [MODULE ...]] [-l] [-em MODULE [MODULE ...]] [-f FLAG [FLAG ...]]
            [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]] [-om MODULE [MODULE ...]] [-o DIR] [-c [CONFIG ...]] [--allow-deadly] [-v] [-d] [--force] [-y] [--dry-run] [--current-config] [--save-wordcloud FILE]
            [--load-wordcloud FILE] [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps] [-a]

Bighuge BLS OSINT Tool

options:
  -h, --help            show this help message and exit
  -n SCAN_NAME, --name SCAN_NAME
                        Name of scan (default: random)
  -m MODULE [MODULE ...], --modules MODULE [MODULE ...]
                        Modules to enable. Choices: affiliates,asn,aspnet_viewstate,azure_tenant,binaryedge,blind_ssrf,bypass403,c99,censys,certspotter,cookie_brute,crobat,crt,dnscommonsrv,dnsdumpster,dnszonetransfer,emailformat,ffuf,ffuf_shortnames,generic_ssrf,getparam_brute,github,gowitness,hackertarget,header_brute,host_header,httpx,hunt,hunterio,iis_shortnames,ipneighbor,leakix,massdns,naabu,ntlm,nuclei,passivetotal,pgp,securitytrails,shodan_dns,skymem,smuggler,sslcert,sublist3r,telerik,threatminer,urlscan,viewdns,wappalyzer,wayback,zoomeye
  -l, --list-modules    List available modules.
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: active,aggressive,brute-force,deadly,passive,portscan,report,safe,slow,subdomain-enum,web
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Disable modules that don't have these flags (e.g. --require-flags passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. --exclude-flags brute-force)
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: csv,http,human,json,neo4j,websocket
  -o DIR, --output-dir DIR
  -c [CONFIG ...], --config [CONFIG ...]
                        custom config file, or configuration options in key=value format: 'modules.shodan.api_key=1234'
  --allow-deadly        Enable running modules tagged as "deadly"
  -v, --verbose         Be more verbose
  -d, --debug           Enable debugging
  --force               Run scan even if module setups fail
  -y, --yes             Skip scan confirmation prompt
  --dry-run             Abort before executing scan
  --current-config      Show current config in YAML format

Target:
  -t TARGET [TARGET ...], --targets TARGET [TARGET ...]
                        Targets to seed the scan
  -w WHITELIST [WHITELIST ...], --whitelist WHITELIST [WHITELIST ...]
                        What's considered in-scope (by default it's the same as --targets)
  -b BLACKLIST [BLACKLIST ...], --blacklist BLACKLIST [BLACKLIST ...]
                        Don't touch these things
  -s, --strict-scope    Don't consider subdomains of target/whitelist to be in-scope

Word cloud:
  Save/load wordlist of common words gathered during a scan

  --save-wordcloud FILE
                        Output wordcloud to custom file when the scan completes
  --load-wordcloud FILE
                        Load wordcloud from a custom file

Module dependencies:
  Control how modules install their dependencies

  --no-deps             Don't install module dependencies
  --force-deps          Force install all module dependencies
  --retry-deps          Try again to install failed module dependencies
  --ignore-failed-deps  Run modules even if they have failed dependencies

Agent:
  Report back to a central server

  -a, --agent-mode      Start in agent mode
~~~

# BBOT Config
BBOT loads its config from these places in the following order:

- `~/.config/bbot/defaults.yml`
- `~/.config/bbot/bbot.yml` <-- Use this one as your main config
- `~/.config/bbot/secrets.yml` <-- Use this one for sensitive stuff like API keys
- command line (via `--config`)

Command-line arguments take precedence over all others. You can give BBOT a custom config file with `--config myconf.yml`, or individual arguments like this: `--config http_proxy=http://127.0.0.1:8080 modules.shodan_dns.api_key=1234`. To display the full and current BBOT config, including any command-line arguments, use `bbot --current-config`.

For explanations of config options, see `defaults.yml` or the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#yaml-config)

# Modules

### Note: You can find more fun and interesting modules at the [Module Playground](https://github.com/blacklanternsecurity/bbot-module-playground). For instructions on how to install these other modules, see the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#module-playground).

| Module           | Needs API Key   | Description                                                       | Flags                                              | Produced Events                                      |
|------------------|-----------------|-------------------------------------------------------------------|----------------------------------------------------|------------------------------------------------------|
| aspnet_viewstate |                 | Parse web pages for viewstates and check them against blacklist3r | active,safe,web                                    | VULNERABILITY                                        |
| bypass403        |                 | Check 403 pages for common bypasses                               | active,aggressive,web                              | FINDING                                              |
| cookie_brute     |                 | Check for common HTTP cookie parameters                           | active,aggressive,brute-force,slow,web             | FINDING                                              |
| dnszonetransfer  |                 | Attempt DNS zone transfers                                        | active,safe,subdomain-enum                         | DNS_NAME                                             |
| ffuf             |                 | A fast web fuzzer written in Go                                   | active,aggressive,brute-force,deadly,web           | URL                                                  |
| ffuf_shortnames  |                 | Use ffuf in combination IIS shortnames                            | active,aggressive,brute-force,web                  | URL                                                  |
| generic_ssrf     |                 | Check for generic SSRFs                                           | active,aggressive,web                              | VULNERABILITY                                        |
| getparam_brute   |                 | Check for common HTTP GET parameters                              | active,aggressive,brute-force,slow,web             | FINDING                                              |
| gowitness        |                 | Take screenshots of webpages                                      | active,safe,web                                    | SCREENSHOT                                           |
| header_brute     |                 | Check for common HTTP header parameters                           | active,aggressive,brute-force,slow,web             | FINDING                                              |
| host_header      |                 | Try common HTTP Host header spoofing techniques                   | active,aggressive,web                              | FINDING                                              |
| httpx            |                 | Visit webpages. Many other modules rely on httpx                  | active,safe,web                                    | HTTP_RESPONSE,URL                                    |
| hunt             |                 | Watch for commonly-exploitable HTTP parameters                    | active,safe,web                                    | FINDING                                              |
| iis_shortnames   |                 | Check for IIS shortname vulnerability                             | active,safe                                        | URL_HINT                                             |
| naabu            |                 | Execute port scans with naabu                                     | active,aggressive,portscan                         | OPEN_TCP_PORT                                        |
| ntlm             |                 | Watch for HTTP endpoints that support NTLM authentication         | active,safe,web                                    | DNS_NAME,FINDING                                     |
| nuclei           |                 | Fast and customisable vulnerability scanner                       | active,aggressive,deadly,web                       | VULNERABILITY                                        |
| smuggler         |                 | Check for HTTP smuggling                                          | active,aggressive,brute-force,slow,web             | FINDING                                              |
| sslcert          |                 | Visit open ports and retrieve SSL certificates                    | active,email-enum,safe,subdomain-enum              | DNS_NAME,EMAIL_ADDRESS                               |
| telerik          |                 | Scan for critical Telerik vulnerabilities                         | active,aggressive,web                              | FINDING,VULNERABILITY                                |
| vhost            |                 | Fuzz for virtual hosts                                            | active,aggressive,brute-force,deadly,slow,web      | DNS_NAME,VHOST                                       |
| wappalyzer       |                 | Extract technologies from web responses                           | active,safe,web                                    | TECHNOLOGY                                           |
| affiliates       |                 | Summarize affiliate domains at the end of a scan                  | passive,report,safe                                |                                                      |
| asn              |                 | Query bgpview.io for ASNs                                         | passive,report,safe,subdomain-enum                 | ASN                                                  |
| azure_tenant     |                 | Query Azure for tenant sister domains                             | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| binaryedge       | X               | Query the BinaryEdge API                                          | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| builtwith        | X               | Query Builtwith.com for subdomains                                | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| c99              | X               | Query the C99 API for subdomains                                  | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| censys           | X               | Query the Censys API                                              | email-enum,passive,safe,subdomain-enum             | DNS_NAME,EMAIL_ADDRESS,IP_ADDRESS,OPEN_PORT,PROTOCOL |
| certspotter      |                 | Query Certspotter's API for subdomains                            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| crobat           |                 | Query Project Crobat for subdomains                               | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| crt              |                 | Query crt.sh (certificate transparency) for subdomains            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| dnscommonsrv     |                 | Check for common SRV records                                      | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| dnsdumpster      |                 | Query dnsdumpster for subdomains                                  | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| emailformat      |                 | Query email-format.com for email addresses                        | email-enum,passive,safe                            | EMAIL_ADDRESS                                        |
| fullhunt         | X               | Query the fullhunt.io API for subdomains                          | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| github           | X               | Query Github's API for related repositories                       | passive,safe,subdomain-enum                        | URL_UNVERIFIED                                       |
| hackertarget     |                 | Query the hackertarget.com API for subdomains                     | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| hunterio         | X               | Query hunter.io for emails                                        | email-enum,passive,safe,subdomain-enum             | DNS_NAME,EMAIL_ADDRESS,URL_UNVERIFIED                |
| ipneighbor       |                 | Look beside IPs in their surrounding subnet                       | aggressive,passive,subdomain-enum                  | IP_ADDRESS                                           |
| leakix           |                 | Query leakix.net for subdomains                                   | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| massdns          |                 | Brute-force subdomains with massdns (highly effective)            | aggressive,brute-force,passive,slow,subdomain-enum | DNS_NAME                                             |
| otx              |                 | Query otx.alienvault.com for subdomains                           | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| passivetotal     | X               | Query the PassiveTotal API for subdomains                         | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| pgp              |                 | Query common PGP servers for email addresses                      | email-enum,passive,safe                            | EMAIL_ADDRESS                                        |
| rapiddns         |                 | Query rapiddns.io for subdomains                                  | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| securitytrails   | X               | Query the SecurityTrails API for subdomains                       | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| shodan_dns       | X               | Query Shodan for subdomains                                       | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| skymem           |                 | Query skymem.info for email addresses                             | email-enum,passive,safe                            | EMAIL_ADDRESS                                        |
| sublist3r        |                 | Query sublist3r's API for subdomains                              | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| threatminer      |                 | Query threatminer's API for subdomains                            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| urlscan          |                 | Query urlscan.io for subdomains                                   | passive,safe,subdomain-enum                        | DNS_NAME,URL_UNVERIFIED                              |
| viewdns          |                 | Query viewdns.info's reverse whois for related domains            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| wayback          |                 | Query archive.org's API for subdomains                            | passive,safe,subdomain-enum                        | DNS_NAME,URL_UNVERIFIED                              |
| zoomeye          | X               | Query ZoomEye's API for subdomains                                | passive,safe,subdomain-enum                        | DNS_NAME                                             |
