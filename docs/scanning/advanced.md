# Advanced

Below you can find some advanced uses of BBOT.

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

## Command-Line Help

<!-- BBOT HELP OUTPUT -->
```text
usage: bbot [-h] [--help-all] [-t TARGET [TARGET ...]]
               [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]]
               [--strict-scope] [-m MODULE [MODULE ...]] [-l]
               [-em MODULE [MODULE ...]] [-f FLAG [FLAG ...]] [-lf]
               [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]]
               [-om MODULE [MODULE ...]] [--allow-deadly] [-n SCAN_NAME]
               [-o DIR] [-c [CONFIG ...]] [-v] [-d] [-s] [--force] [-y]
               [--dry-run] [--current-config]
               [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps]
               [-a] [--version]

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
                        Modules to enable. Choices: affiliates,anubisdb,asn,azure_realm,azure_tenant,badsecrets,bevigil,binaryedge,bucket_amazon,bucket_azure,bucket_digitalocean,bucket_file_enum,bucket_firebase,bucket_google,builtwith,bypass403,c99,censys,certspotter,chaos,columbus,credshed,crobat,crt,dehashed,digitorus,dnscommonsrv,dnsdumpster,dnszonetransfer,emailformat,ffuf,ffuf_shortnames,filedownload,fingerprintx,fullhunt,generic_ssrf,git,github,gowitness,hackertarget,host_header,httpx,hunt,hunterio,iis_shortnames,ip2location,ipneighbor,ipstack,leakix,masscan,massdns,myssl,nmap,nsec,ntlm,nuclei,oauth,otx,paramminer_cookies,paramminer_getparams,paramminer_headers,passivetotal,pgp,rapiddns,riddler,robots,secretsdb,securitytrails,shodan_dns,sitedossier,skymem,smuggler,social,sslcert,subdomain_hijack,subdomaincenter,sublist3r,telerik,threatminer,url_manipulation,urlscan,vhost,viewdns,virustotal,wafw00f,wappalyzer,wayback,zoomeye
  -l, --list-modules    List available modules.
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: active,affiliates,aggressive,cloud-enum,deadly,email-enum,iis-shortnames,passive,portscan,report,safe,service-enum,slow,social-enum,subdomain-enum,subdomain-hijack,web-basic,web-paramminer,web-screenshots,web-thorough
  -lf, --list-flags     List available flags.
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Only enable modules with these flags (e.g. -rf passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. -ef aggressive)
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: asset_inventory,csv,discord,http,human,json,neo4j,python,slack,subdomains,teams,web_report,websocket
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

EXAMPLES

    Subdomains:
        bbot -t evilcorp.com -f subdomain-enum

    Subdomains (passive only):
        bbot -t evilcorp.com -f subdomain-enum -rf passive

    Subdomains + port scan + web screenshots:
        bbot -t evilcorp.com -f subdomain-enum -m nmap gowitness -n my_scan -o .

    Subdomains + basic web scan:
        bbot -t evilcorp.com -f subdomain-enum web-basic

    Web spider:
        bbot -t www.evilcorp.com -m httpx robots badsecrets secretsdb -c web_spider_distance=2 web_spider_depth=2

    Everything everywhere all at once:
        bbot -t evilcorp.com -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly

    List modules:
        bbot -l

    List flags:
        bbot -lf

```
<!-- END BBOT HELP OUTPUT -->
