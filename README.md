![bbot_banner](https://user-images.githubusercontent.com/20261699/158000235-6c1ace81-a267-4f8e-90a1-f4c16884ebac.png)

# BEE·bot
### OSINT automation for hackers.

[![Python Version](https://img.shields.io/badge/python-3.9+-FF8400)](https://www.python.org) [![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/blacklanternsecurity/bbot/blob/dev/LICENSE) [![Tests](https://github.com/blacklanternsecurity/bbot/workflows/tests/badge.svg)](https://github.com/blacklanternsecurity/bbot/actions?query=workflow%3A"tests") [![Codecov](https://codecov.io/gh/blacklanternsecurity/bbot/branch/dev/graph/badge.svg?token=IR5AZBDM5K)](https://codecov.io/gh/blacklanternsecurity/bbot)

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

Troubleshooting:
- `Fatal error from pip prevented installation.`
- `ERROR: No matching distribution found for bbot`
- `bash: /home/user/.local/bin/bbot: /home/user/.local/pipx/venvs/bbot/bin/python: bad interpreter`

If you get errors resembling any of the above, you need to do something like this:
~~~bash
# install a newer version of python
sudo apt install python3.9 python3.9-venv
# install pipx
python3.9 -m pip install --user pipx
# add pipx to your path
python3.9 -m pipx ensurepath
# reboot
reboot
# install bbot
python3.9 -m pipx install bbot
# run bbot
bbot --help
# if that doesn't work, you may want to go home and rethink your life.
~~~

## Scanning with BBOT

### Examples
~~~bash
# list modules
bbot -l

# subdomain enumeration
bbot --flags subdomain-enum --targets evilcorp.com

# passive only
bbot --flags passive --targets evilcorp.com

# web screenshots with gowitness
bbot --modules naabu httpx gowitness --name my_scan --output-dir . --targets evilcorp.com 1.2.3.4/28 4.3.2.1 targets.txt

# web spider (search for emails, etc.)
bbot -m httpx -c web_spider_distance=2 -t www.evilcorp.com
~~~

### Notes

Running a BBOT scan is as simple as specifying a target and a list of modules.

There is **one module**, however, that's **especially important**, and that's `httpx`. BBOT's `httpx` module is the core of its web capability and used heavily by other modules. `httpx` is responsible for visiting webpages and verifying the validity of URLS. For this reason, if you want to run any web-related module, e.g. `wappalyzer`, `gowitness`, `nuclei`, etc., you'll need to enable `httpx` as well.

`httpx` is especially powerful because it enables other BBOT modules (like `excavate`) to passively parse web pages for goodies like cleartext passwords, emails, subdomains, etc.

## Using BBOT as a Python library
~~~python
from bbot.scanner import Scanner

# this will prompt for a sudo password on first run
# if you prefer, you can export BBOT_SUDO_PASS instead
scan = Scanner("evilcorp.com", "1.2.3.0/24", modules=["naabu"], output_modules=["http"])

len(scan.target) # --> 257
"1.2.3.4" in scan.target # --> True
"4.3.2.1" in scan.target # --> False
"www.evilcorp.com" in scan.target # --> True

scan.start()
~~~

# Output
BBOT outputs to STDOUT by default, but it can output in multiple formats simultaneously (with `--output-module`).
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

# Modules
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
| binaryedge       | X               | Query the BinaryEdge API                                          | passive,safe,subdomain-enum                        | DNS_NAME,EMAIL_ADDRESS,IP_ADDRESS,OPEN_PORT,PROTOCOL |
| c99              | X               | Query the C99 API for subdomains                                  | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| censys           | X               | Query the Censys API                                              | email-enum,passive,safe,subdomain-enum             | DNS_NAME,EMAIL_ADDRESS,IP_ADDRESS,OPEN_PORT,PROTOCOL |
| certspotter      |                 | Query Certspotter's API for subdomains                            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| crobat           |                 | Query Project Crobat for subdomains                               | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| crt              |                 | Query crt.sh (certificate transparency) for subdomains            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| dnscommonsrv     |                 | Check for common SRV records                                      | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| dnsdumpster      |                 | Query dnsdumpster for subdomains                                  | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| emailformat      |                 | Query email-format.com for email addresses                        | email-enum,passive,safe                            | EMAIL_ADDRESS                                        |
| github           | X               | Query Github's API for related repositories                       | passive,safe,subdomain-enum                        | URL_UNVERIFIED                                       |
| hackertarget     |                 | Query the hackertarget.com API for subdomains                     | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| hunterio         | X               | Query hunter.io for emails                                        | email-enum,passive,safe,subdomain-enum             | DNS_NAME,EMAIL_ADDRESS,URL_UNVERIFIED                |
| ipneighbor       |                 | Look beside IPs in their surrounding subnet                       | aggressive,passive,subdomain-enum                  | IP_ADDRESS                                           |
| leakix           |                 | Query leakix.net for subdomains                                   | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| massdns          |                 | Brute-force subdomains with massdns (highly effective)            | aggressive,brute-force,passive,slow,subdomain-enum | DNS_NAME                                             |
| passivetotal     | X               | Query the PassiveTotal API for subdomains                         | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| pgp              |                 | Query common PGP servers for email addresses                      | email-enum,passive,safe                            | EMAIL_ADDRESS                                        |
| securitytrails   | X               | Query the SecurityTrails API for subdomains                       | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| shodan_dns       | X               | Query Shodan for subdomains                                       | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| skymem           |                 | Query skymem.info for email addresses                             | email-enum,passive,safe                            | EMAIL_ADDRESS                                        |
| sublist3r        |                 | Query sublist3r's API for subdomains                              | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| threatminer      |                 | Query threatminer's API for subdomains                            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| urlscan          |                 | Query urlscan.io for subdomains                                   | passive,safe,subdomain-enum                        | DNS_NAME,URL_UNVERIFIED                              |
| viewdns          |                 | Query viewdns.info's reverse whois for related domains            | passive,safe,subdomain-enum                        | DNS_NAME                                             |
| wayback          |                 | Query archive.org's API for subdomains                            | passive,safe,subdomain-enum                        | DNS_NAME,URL_UNVERIFIED                              |
| zoomeye          | X               | Query ZoomEye's API for subdomains                                | passive,safe,subdomain-enum                        | DNS_NAME                                             |

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
- `~/.config/bbot/bbot.yml` <-- Use this one for everything else
- `~/.config/bbot/secrets.yml` <-- Use this one for API keys and stuff
- command line (via `--config`)

Command-line arguments take precedence over all others. You can give BBOT a custom config file with `--config myconf.yml`, or individual arguments like this: `--config http_proxy=http://127.0.0.1:8080 modules.shodan_dns.api_key=1234`. To display the full and current BBOT config, including any command-line arguments, use `bbot --current-config`.

~~~yaml
### BASIC OPTIONS ###

# BBOT working directory
home: ~/.bbot
# How far out from the main scope to search
scope_search_distance: 1
# Don't output events that are further than this from the main scope
scope_report_distance: 1
# How far out from the main scope to resolve DNS names / IPs
scope_dns_search_distance: 2
# Limit the number of BBOT threads
max_threads: 20
# Limit the number of DNS threads
max_dns_threads: 100
# Limit the number of brute force modules that can run at one time
max_brute_forcers: 2


### ADVANCED OPTIONS ###

# Infer certain events from others, e.g. IPs from IP ranges, DNS_NAMEs from URLs, etc.
speculate: True
# Passively search event data for URLs, hostnames, emails, etc.
excavate: True
# Summarize activity at the end of a scan
aggregate: True
# HTTP proxy
http_proxy: 
# HTTP timeout (for Python requests; API calls, etc.)
http_timeout: 30
# HTTP timeout (for httpx)
httpx_timeout: 5
# Enable/disable debug messages for web requests/responses
http_debug: false
# Set the maximum number of HTTP links that can be followed in a row (0 == no spidering allowed)
web_spider_distance: 0
# Set the maximum directory depth for the web spider
web_spider_depth: 1
# Generate new DNS_NAME and IP_ADDRESS events through DNS resolution
dns_resolution: true
# DNS query timeout
dns_timeout: 10
# Disable BBOT's smart DNS wildcard handling for select domains
dns_wildcard_ignore: []
# How many sanity checks to make when verifying wildcard DNS
# Increase this value if BBOT's wildcard detection isn't working
dns_wildcard_tests: 5
# Skip DNS requests for a certain domain and rdtype after encountering this many timeouts or SERVFAILs
# This helps prevent faulty DNS servers from hanging up the scan
dns_abort_threshold: 10
# Enable/disable filtering of PTR records containing IP addresses
dns_filter_ptrs: true
# Enable/disable debug messages for dns queries
dns_debug: false
# Whether to verify SSL certificates
ssl_verify: false
# How many scan results to keep before cleaning up the older ones
keep_scans: 20
# Web user-agent
user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
# Completely ignore URLs with these extensions
url_extension_blacklist:
    # images
    - png
    - jpg
    - bmp
    - ico
    - jpeg
    - gif
    - svg
    # web/fonts
    - css
    - woff
    - woff2
    - ttf
    # audio
    - mp3
    - m4a
    - wav
    - flac
    # video
    - mp4
    - mkv
    - avi
    - wmv
    - mov
    - flv
    - webm
# Distribute URLs with these extensions only to httpx (these are omitted from output)
url_extension_httpx_only:
    - js
# Don't output these types of events (they are still distributed to modules)
omit_event_types:
    - HTTP_RESPONSE
    - URL_UNVERIFIED
# URL of BBOT server
agent_url: ''
# Agent Bearer authentication token
agent_token: ''

# Custom interactsh server settings
interactsh_server: null
interactsh_token: null
interactsh_disable: false
~~~

# Devving on BBOT

## Installation

Clone BBOT and set up a developent environment with Poetry:
~~~bash
git clone git@github.com:blacklanternsecurity/bbot.git && cd bbot

pip install poetry
poetry shell
poetry install

bbot --help
~~~

## Writing modules
Writing a module is easy and requires only a basic understanding of Python. It consists of a few steps:

1. Create a new `.py` file in `bbot/modules`
1. At the top of the file, import `BaseModule`
1. Declare a class that inherits from `BaseModule`
    - the class must have the same name as your file (case-insensitive)
1. Define (via `watched_events` and `produced_events`) what types of events your module consumes
1. Define (via `flags`) whether your module is `active` or `passive`
1. Override `.handle_event()`
    - this is where you put your custom code

Here is a simple example of a working module (`bbot/modules/mymodule.py`):
~~~python
from bbot.modules.base import BaseModule

class MyModule(BaseModule):
    """
    Reverse-resolve DNS_NAMEs
    """
    watched_events = ["DNS_NAME"]
    produced_events = ["IP_ADDRESS"]
    flags = ["passive"]

    def handle_event(self, event):
        for ip in self.helpers.resolve(event.data):
            self.emit_event(ip, "IP_ADDRESS", source=event)
~~~

## Feature: Dependency Handling

BBOT automates module dependencies with **Ansible**. If your module has external dependencies (including pip dependencies), you can specify them in the `deps_*` attributes of your module.

~~~python
class MyModule(BaseModule):
    ...
    deps_pip = ["beautifulsoup4"]
    deps_apt = ["chromium-browser"]
    deps_ansible = [
        {
            "name": "Download massdns source code",
            "git": {
                "repo": "https://github.com/blechschmidt/massdns.git",
                "dest": "{BBOT_TEMP}/massdns",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build massdns",
            "command": {"chdir": "{BBOT_TEMP}/massdns", "cmd": "make", "creates": "{BBOT_TEMP}/massdns/bin/massdns"},
        },
        {
            "name": "Install massdns",
            "copy": {"src": "{BBOT_TEMP}/massdns/bin/massdns", "dest": "{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]
~~~

## Module helpers
Modules have easy access to scan information (via `self.scan`) and helper functions (via `self.helpers`):
~~~python
# Access scan target:
if event in self.scan.target:
    self.info(f"{event} is part of target!")

# Use a helper function
if not self.helpers.is_domain(event.data):
    self.warning(f"{event} is not a domain.")

# Access module config
if not self.config.api_key:
    self.error(f"No API key specified for module {self.name}!")

# Make a DNS query
mx_records = self.helpers.resolve("evilcorp.com", type="mx")

# Make a web request
response = self.helpers.request("https://evilcorp.com")

# Download a file
filename = self.helpers.download("https://example.com/test.pdf", cache_hrs=720)

# Download a wordlist
filename = self.helpers.wordlist("https://example.com/wordlist.txt", lines=1000)
filename = self.helpers.wordlist("/tmp/wordlist.txt", lines=1000)

# Reverse resolve IP
ptrs = self.helpers.resolve("8.8.8.8")

# Execute a shell command
process = self.helpers.run(["ls", "-lah"])
log.info(process.stdout)

# Use the shared thread pool
# limit threads by setting self.config.max_threads
futures = {}
for url in urls:
    future = self.submit_task(self.helpers.request, url)
    futures[future] = url

for future in self.helpers.as_completed(futures):
    url = futures[future]
    response = future.result()
    if getattr(response, "status_code", 0) == 200:
        log.success(f"Found URL: {url}")

# Access the global word cloud
# The word cloud contains commonly-encountered words from the scan
# These words come from dns names, etc., and you can use them for 
# smart brute-forcing of subdomains, vhosts, storage buckets, etc.
self.helpers.word_cloud
# {"www": 1, black": 3, "lantern": 1, "security": 1, ...}
self.helpers.word_cloud.modifiers()
# {"1", "2", "3", "dev", "api", "test", "qa", ...}
self.helpers.word_cloud.mutations("www")
"""
[
    ("www", "dev"),
    ("dev", "www"),
    ("www", "api"),
    ("api", "www"),
    ("www", "1"),
    ("1", "www")
]
"""
~~~

## Run tests
~~~bash
# run tests
bbot/test/run_tests.sh

# re-run a specific test
pytest --disable-warnings --log-cli-level=ERROR -k test_modules

# format with black
black .
~~~

## Adding a dependency
~~~
1. poetry add <package>
~~~

# Credit
BBOT is written by @TheTechromancer. Web hacking in BBOT is made possible by @pmueller-bls, who wrote most of the web-oriented modules and helpers. Thanks to @kerrymilan for his work on the agent feature and for his expertise on Ansible and Neo4j.

Very special thanks to the following people who made BBOT possible:
- Steve Micallef (@smicallef) for creating Spiderfoot, by which BBOT is heavily inspired
- Aleksei Kornev (@alekseiko) for allowing us ownership of the `bbot` Pypi repository <3
