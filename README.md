![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

# BEE·bot
### OSINT automation for hackers.

~~~bash
pip install bbot
~~~

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![Tests](https://github.com/blacklanternsecurity/bbot/actions/workflows/tests.yml/badge.svg?branch=stable)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot)

![bbot-demo](https://user-images.githubusercontent.com/20261699/217346759-d5bf56c3-3936-43f7-ad14-4d73d2cd1417.gif)

### **BBOT** is a **recursive**, **modular** OSINT framework inspired by Spiderfoot.

BBOT can execute the entire OSINT process in a single command: subdomain enumeration, port scans, web screenshots (with `gowitness`), vulnerability scanning (with `nuclei`), and much more. BBOT has over **80 modules** and counting.

Read our [blog post](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off) to find out why BBOT is the most thorough subdomain enumeration tool available.

![graphs-small](https://user-images.githubusercontent.com/20261699/199602154-14c71a93-57aa-4ac0-ad81-87ce64fbffc7.png)

## Installation ([pip](https://pypi.org/project/bbot/))
Note: installing in a virtualenv (e.g. via `pipx`) is recommended
~~~bash
# stable version
pip install bbot

# bleeding edge (dev branch)
pip install --pre bbot

bbot --help
~~~
Prerequisites:
- Linux (Windows, including WSL is not supported)
- Python 3.9 or newer

## Installation ([Docker](https://hub.docker.com/r/blacklanternsecurity/bbot))
~~~bash
# bleeding edge (dev)
docker run -it blacklanternsecurity/bbot --help

# stable
docker run -it blacklanternsecurity/bbot:stable --help

# note: alternatively there is a helper script that will map docker volumes to persist your BBOT scan data:
./bbot-docker.sh --help
~~~

If you need help with installation, please refer to the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#installation).

See also: [Release History](https://github.com/blacklanternsecurity/bbot/wiki/Release-History)

## Scanning with BBOT

### Examples
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

### Targets

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

#### Whitelists / Blacklists

BBOT's whitelist determines what's considered to be in-scope. By default, the whitelist is simply your target. But if you want more granular scope control, you can override it with `--whitelist` (or add a `--blacklist`).

~~~bash
# seed a scan with two domains, but only consider assets to be in scope if they are inside 1.2.3.0/24
bbot -t evilcorp.com evilcorp.co.uk --whitelist 1.2.3.0/24 --blacklist test.evilcorp.com 1.2.3.4 blacklist.txt
~~~

Visit the wiki for more [tips and tricks](https://github.com/blacklanternsecurity/bbot/wiki#tips-and-tricks).

## Using BBOT as a Python library
~~~python
from bbot.scanner import Scanner

# any number of targets can be specified
scan = Scanner("evilcorp.com", "1.2.3.0/24", modules=["httpx", "sslcert"])
for event in scan.start():
    print(event.json())
~~~

# Output
By default, BBOT saves its output in TXT, JSON, and CSV formats. To enable more output modules, you can use `--output-module`.
~~~bash
# tee to a file
bbot -f subdomain-enum -t evilcorp.com | tee evilcorp.txt

# output to JSON
bbot --output-module json -f subdomain-enum -t evilcorp.com | jq

# output asset inventory in current directory
bbot -o . --output-module asset_inventory -f subdomain-enum -t evilcorp.com
~~~
For every scan, BBOT generates a unique and mildly-entertaining name like `demonic_jimmy`. Output for that scan, including the word cloud and any gowitness screenshots, etc., are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed. You can change the location of BBOT's output with `--output`, and you can also pick a custom scan name with `--name`.

If you reuse a scan name, it will append to its original output files and leverage the previous word cloud.

# Neo4j
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

# Usage
~~~
$ bbot --help
usage: bbot [-h] [--help-all] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]] [--strict-scope] [-n SCAN_NAME] [-m MODULE [MODULE ...]] [-l] [-em MODULE [MODULE ...]]
            [-f FLAG [FLAG ...]] [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]] [-om MODULE [MODULE ...]] [-o DIR] [-c [CONFIG ...]] [--allow-deadly] [-v] [-d] [-s] [--force] [-y] [--dry-run] [--current-config]
            [--save-wordcloud FILE] [--load-wordcloud FILE] [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps] [-a] [--version]

Bighuge BLS OSINT Tool

options:
  -h, --help            show this help message and exit
  --help-all            Display full help including module config options
  -n SCAN_NAME, --name SCAN_NAME
                        Name of scan (default: random)
  -m MODULE [MODULE ...], --modules MODULE [MODULE ...]
                        Modules to enable. Choices: affiliates,anubisdb,asn,azure_tenant,badsecrets,bevigil,binaryedge,bucket_aws,bucket_azure,bucket_digitalocean,bucket_firebase,bucket_gcp,builtwith,bypass403,c99,censys,certspotter,crobat,crt,dnscommonsrv,dnsdumpster,dnszonetransfer,emailformat,ffuf,ffuf_shortnames,fingerprintx,fullhunt,generic_ssrf,github,gowitness,hackertarget,host_header,httpx,hunt,hunterio,iis_shortnames,ipneighbor,ipstack,leakix,masscan,massdns,naabu,ntlm,nuclei,otx,paramminer_cookies,paramminer_getparams,paramminer_headers,passivetotal,pgp,rapiddns,riddler,robots,secretsdb,securitytrails,shodan_dns,skymem,smuggler,social,sslcert,subdomain_hijack,sublist3r,telerik,threatminer,url_manipulation,urlscan,vhost,viewdns,virustotal,wafw00f,wappalyzer,wayback,zoomeye
  -l, --list-modules    List available modules.
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: active,affiliates,aggressive,cloud-enum,deadly,email-enum,iis-shortnames,passive,portscan,report,safe,service-enum,slow,social-enum,subdomain-enum,subdomain-hijack,web-basic,web-paramminer,web-screenshots,web-thorough
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Disable modules that don't have these flags (e.g. -rf passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. -ef aggressive)
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: asset_inventory,csv,http,human,json,neo4j,python,web_report,websocket
  -o DIR, --output-dir DIR
  -c [CONFIG ...], --config [CONFIG ...]
                        custom config file, or configuration options in key=value format: 'modules.shodan.api_key=1234'
  --allow-deadly        Enable the use of highly aggressive modules
  -v, --verbose         Be more verbose
  -d, --debug           Enable debugging
  -s, --silent          Be quiet
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
  --strict-scope        Don't consider subdomains of target/whitelist to be in-scope

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
  --install-all-deps    Install dependencies for all modules

Agent:
  Report back to a central server

  -a, --agent-mode      Start in agent mode

Misc:
  --version             show BBOT version and exit
~~~

# BBOT Config
BBOT loads its config from these places in the following order:

- `~/.config/bbot/bbot.yml` <-- Use this one as your main config
- `~/.config/bbot/secrets.yml` <-- Use this one for sensitive stuff like API keys
- command line (`--config`)

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

# Modules

### Note: You can find more fun and interesting modules at the [Module Playground](https://github.com/blacklanternsecurity/bbot-module-playground). For instructions on how to install these other modules, see the [wiki](https://github.com/blacklanternsecurity/bbot/wiki#module-playground).

To see modules' options (how to change wordlists, thread count, etc.), use `--help-all`.

~~~
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| Module               | Type     | Needs   | Description                              | Flags                                    | Produced Events                          |
|                      |          | API     |                                          |                                          |                                          |
|                      |          | Key     |                                          |                                          |                                          |
+======================+==========+=========+==========================================+==========================================+==========================================+
| badsecrets           | scan     |         | Library for detecting known or weak      | active,safe,web-basic,web-thorough       | FINDING,VULNERABILITY                    |
|                      |          |         | secrets across many web frameworks       |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bucket_aws           | scan     |         | Check for S3 buckets related to target   | active,cloud-enum,safe,web-basic,web-    | FINDING,STORAGE_BUCKET                   |
|                      |          |         |                                          | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bucket_azure         | scan     |         | Check for Azure storage blobs related to | active,cloud-enum,safe,web-basic,web-    | FINDING,STORAGE_BUCKET                   |
|                      |          |         | target                                   | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bucket_digitalocean  | scan     |         | Check for DigitalOcean spaces related to | active,cloud-enum,safe,slow,web-thorough | FINDING,STORAGE_BUCKET                   |
|                      |          |         | target                                   |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bucket_firebase      | scan     |         | Check for open Firebase databases        | active,cloud-enum,safe,web-basic,web-    | FINDING,STORAGE_BUCKET                   |
|                      |          |         | related to target                        | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bucket_gcp           | scan     |         | Check for Google object storage related  | active,cloud-enum,safe,web-basic,web-    | FINDING,STORAGE_BUCKET                   |
|                      |          |         | to target                                | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bypass403            | scan     |         | Check 403 pages for common bypasses      | active,aggressive,web-thorough           | FINDING                                  |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| dnszonetransfer      | scan     |         | Attempt DNS zone transfers               | active,safe,subdomain-enum               | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| ffuf                 | scan     |         | A fast web fuzzer written in Go          | active,aggressive,deadly                 | URL_UNVERIFIED                           |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| ffuf_shortnames      | scan     |         | Use ffuf in combination IIS shortnames   | active,aggressive,iis-shortnames,web-    | URL_UNVERIFIED                           |
|                      |          |         |                                          | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| fingerprintx         | scan     |         | Fingerprint exposed services like RDP,   | active,safe,service-enum,slow            | PROTOCOL                                 |
|                      |          |         | SSH, MySQL, etc.                         |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| generic_ssrf         | scan     |         | Check for generic SSRFs                  | active,aggressive,web-thorough           | VULNERABILITY                            |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| gowitness            | scan     |         | Take screenshots of webpages             | active,safe,web-screenshots              | TECHNOLOGY,URL,URL_UNVERIFIED,WEBSCREENS |
|                      |          |         |                                          |                                          | HOT                                      |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| host_header          | scan     |         | Try common HTTP Host header spoofing     | active,aggressive,web-thorough           | FINDING                                  |
|                      |          |         | techniques                               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| httpx                | scan     |         | Visit webpages. Many other modules rely  | active,cloud-enum,safe,social-           | HTTP_RESPONSE,URL                        |
|                      |          |         | on httpx                                 | enum,subdomain-enum,web-basic,web-       |                                          |
|                      |          |         |                                          | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| hunt                 | scan     |         | Watch for commonly-exploitable HTTP      | active,safe,web-basic,web-thorough       | FINDING                                  |
|                      |          |         | parameters                               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| iis_shortnames       | scan     |         | Check for IIS shortname vulnerability    | active,iis-shortnames,safe,web-          | URL_HINT                                 |
|                      |          |         |                                          | basic,web-thorough                       |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| masscan              | scan     |         | Port scan IP subnets with masscan        | active,aggressive,portscan               | OPEN_TCP_PORT                            |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| naabu                | scan     |         | Execute port scans with naabu            | active,aggressive,portscan,web-thorough  | OPEN_TCP_PORT                            |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| ntlm                 | scan     |         | Watch for HTTP endpoints that support    | active,safe,web-basic,web-thorough       | DNS_NAME,FINDING                         |
|                      |          |         | NTLM authentication                      |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| nuclei               | scan     |         | Fast and customisable vulnerability      | active,aggressive,deadly                 | FINDING,VULNERABILITY                    |
|                      |          |         | scanner                                  |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| paramminer_cookies   | scan     |         | Smart brute-force to check for common    | active,aggressive,slow,web-paramminer    | FINDING                                  |
|                      |          |         | HTTP cookie parameters                   |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| paramminer_getparams | scan     |         | Use smart brute-force to check for       | active,aggressive,slow,web-paramminer    | FINDING                                  |
|                      |          |         | common HTTP GET parameters               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| paramminer_headers   | scan     |         | Use smart brute-force to check for       | active,aggressive,slow,web-paramminer    | FINDING                                  |
|                      |          |         | common HTTP header parameters            |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| robots               | scan     |         | Look for and parse robots.txt            | active,safe,web-basic,web-thorough       | URL_UNVERIFIED                           |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| secretsdb            | scan     |         | Detect common secrets with secrets-      | active,safe,web-basic,web-thorough       | FINDING                                  |
|                      |          |         | patterns-db                              |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| smuggler             | scan     |         | Check for HTTP smuggling                 | active,aggressive,slow,web-thorough      | FINDING                                  |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| social               | scan     |         | Look for social media links in webpages  | active,safe,social-enum                  | SOCIAL                                   |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| sslcert              | scan     |         | Visit open ports and retrieve SSL        | active,affiliates,email-                 | DNS_NAME,EMAIL_ADDRESS                   |
|                      |          |         | certificates                             | enum,safe,subdomain-enum,web-basic,web-  |                                          |
|                      |          |         |                                          | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| subdomain_hijack     | scan     |         | Detect hijackable subdomains             | active,cloud-enum,safe,subdomain-        | FINDING                                  |
|                      |          |         |                                          | enum,subdomain-hijack,web-basic,web-     |                                          |
|                      |          |         |                                          | thorough                                 |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| telerik              | scan     |         | Scan for critical Telerik                | active,aggressive,slow,web-thorough      | FINDING,VULNERABILITY                    |
|                      |          |         | vulnerabilities                          |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| url_manipulation     | scan     |         | Attempt to identify URL parsing/routing  | active,aggressive,web-thorough           | FINDING                                  |
|                      |          |         | based vulnerabilities                    |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| vhost                | scan     |         | Fuzz for virtual hosts                   | active,aggressive,deadly,slow            | DNS_NAME,VHOST                           |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| wafw00f              | scan     |         | Web Application Firewall Fingerprinting  | active,aggressive                        | WAF                                      |
|                      |          |         | Tool                                     |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| wappalyzer           | scan     |         | Extract technologies from web responses  | active,safe,web-basic,web-thorough       | TECHNOLOGY                               |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| affiliates           | scan     |         | Summarize affiliate domains at the end   | passive,report,safe                      |                                          |
|                      |          |         | of a scan                                |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| anubisdb             | scan     |         | Query jldc.me's database for subdomains  | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| asn                  | scan     |         | Query ripe and bgpview.io for ASNs       | passive,report,safe,subdomain-enum       | ASN                                      |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| azure_tenant         | scan     |         | Query Azure for tenant sister domains    | affiliates,passive,safe,subdomain-enum   | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| bevigil              | scan     | X       | Retrieve OSINT data from mobile          | passive,safe,subdomain-enum              | DNS_NAME,URL_UNVERIFIED                  |
|                      |          |         | applications using BeVigil               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| binaryedge           | scan     | X       | Query the BinaryEdge API                 | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| builtwith            | scan     | X       | Query Builtwith.com for subdomains       | affiliates,passive,safe,subdomain-enum   | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| c99                  | scan     | X       | Query the C99 API for subdomains         | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| censys               | scan     | X       | Query the Censys API                     | email-enum,passive,safe,subdomain-enum   | DNS_NAME,EMAIL_ADDRESS,IP_ADDRESS,OPEN_P |
|                      |          |         |                                          |                                          | ORT,PROTOCOL                             |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| certspotter          | scan     |         | Query Certspotter's API for subdomains   | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| crobat               | scan     |         | Query Project Crobat for subdomains      | passive,safe                             | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| crt                  | scan     |         | Query crt.sh (certificate transparency)  | passive,safe,subdomain-enum              | DNS_NAME                                 |
|                      |          |         | for subdomains                           |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| dnscommonsrv         | scan     |         | Check for common SRV records             | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| dnsdumpster          | scan     |         | Query dnsdumpster for subdomains         | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| emailformat          | scan     |         | Query email-format.com for email         | email-enum,passive,safe                  | EMAIL_ADDRESS                            |
|                      |          |         | addresses                                |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| fullhunt             | scan     | X       | Query the fullhunt.io API for subdomains | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| github               | scan     | X       | Query Github's API for related           | passive,safe,subdomain-enum              | URL_UNVERIFIED                           |
|                      |          |         | repositories                             |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| hackertarget         | scan     |         | Query the hackertarget.com API for       | passive,safe,subdomain-enum              | DNS_NAME                                 |
|                      |          |         | subdomains                               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| hunterio             | scan     | X       | Query hunter.io for emails               | email-enum,passive,safe,subdomain-enum   | DNS_NAME,EMAIL_ADDRESS,URL_UNVERIFIED    |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| ipneighbor           | scan     |         | Look beside IPs in their surrounding     | aggressive,passive,subdomain-enum        | IP_ADDRESS                               |
|                      |          |         | subnet                                   |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| ipstack              | scan     | X       | Query IPStack's API for GeoIP            | passive,safe                             | GEOLOCATION                              |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| leakix               | scan     |         | Query leakix.net for subdomains          | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| massdns              | scan     |         | Brute-force subdomains with massdns      | aggressive,passive,slow,subdomain-enum   | DNS_NAME                                 |
|                      |          |         | (highly effective)                       |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| otx                  | scan     |         | Query otx.alienvault.com for subdomains  | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| passivetotal         | scan     | X       | Query the PassiveTotal API for           | passive,safe,subdomain-enum              | DNS_NAME                                 |
|                      |          |         | subdomains                               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| pgp                  | scan     |         | Query common PGP servers for email       | email-enum,passive,safe                  | EMAIL_ADDRESS                            |
|                      |          |         | addresses                                |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| rapiddns             | scan     |         | Query rapiddns.io for subdomains         | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| riddler              | scan     |         | Query riddler.io for subdomains          | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| securitytrails       | scan     | X       | Query the SecurityTrails API for         | passive,safe,subdomain-enum              | DNS_NAME                                 |
|                      |          |         | subdomains                               |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| shodan_dns           | scan     | X       | Query Shodan for subdomains              | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| skymem               | scan     |         | Query skymem.info for email addresses    | email-enum,passive,safe                  | EMAIL_ADDRESS                            |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| sublist3r            | scan     |         | Query sublist3r's API for subdomains     | passive,safe                             | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| threatminer          | scan     |         | Query threatminer's API for subdomains   | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| urlscan              | scan     |         | Query urlscan.io for subdomains          | passive,safe,subdomain-enum              | DNS_NAME,URL_UNVERIFIED                  |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| viewdns              | scan     |         | Query viewdns.info's reverse whois for   | affiliates,passive,safe                  | DNS_NAME                                 |
|                      |          |         | related domains                          |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| virustotal           | scan     | X       | Query VirusTotal's API for subdomains    | passive,safe,subdomain-enum              | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| wayback              | scan     |         | Query archive.org's API for subdomains   | passive,safe,subdomain-enum              | DNS_NAME,URL_UNVERIFIED                  |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| zoomeye              | scan     | X       | Query ZoomEye's API for subdomains       | affiliates,passive,safe,subdomain-enum   | DNS_NAME                                 |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| asset_inventory      | output   |         | Output to an asset inventory style       |                                          |                                          |
|                      |          |         | flattened CSV file                       |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| csv                  | output   |         | Output to CSV                            |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| http                 | output   |         | Send every event to a custom URL via a   |                                          |                                          |
|                      |          |         | web request                              |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| human                | output   |         | Output to text                           |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| json                 | output   |         | Output to JSON                           |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| neo4j                | output   |         | Output to Neo4j                          |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| python               | output   |         | Output via Python API                    |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| web_report           | output   |         | Create a markdown report with web assets |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| websocket            | output   |         | Output to websockets                     |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| aggregate            | internal |         | Summarize statistics at the end of a     | passive,safe                             |                                          |
|                      |          |         | scan                                     |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| excavate             | internal |         | Passively extract juicy tidbits from     | passive                                  | URL_UNVERIFIED                           |
|                      |          |         | scan data                                |                                          |                                          |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
| speculate            | internal |         | Derive certain event types from others   | passive                                  | DNS_NAME,FINDING,IP_ADDRESS,OPEN_TCP_POR |
|                      |          |         | by common sense                          |                                          | T                                        |
+----------------------+----------+---------+------------------------------------------+------------------------------------------+------------------------------------------+
~~~

# Credit

BBOT is written by @TheTechromancer. Web hacking in BBOT is made possible by @liquidsec, who wrote most of the web modules and helpers.

Very special thanks to the following people who made BBOT possible:

- @kerrymilan for his Neo4j and Ansible expertise
- Steve Micallef (@smicallef) for creating Spiderfoot
- Aleksei Kornev (@alekseiko) for allowing us ownership of the bbot Pypi repository <3
