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
usage: bbot [-h] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]] [-b BLACKLIST [BLACKLIST ...]] [--strict-scope] [-p [PRESET ...]] [-c [CONFIG ...]] [-lp]
               [-m MODULE [MODULE ...]] [-l] [-lmo] [-em MODULE [MODULE ...]] [-f FLAG [FLAG ...]] [-lf] [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]] [-om MODULE [MODULE ...]]
               [--allow-deadly] [-n SCAN_NAME] [-o DIR] [-v] [-d] [-s] [--force] [-y] [--dry-run] [--current-preset] [--current-preset-full]
               [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps] [--version]

Bighuge BLS OSINT Tool

options:
  -h, --help            show this help message and exit

Target:
  -t TARGET [TARGET ...], --targets TARGET [TARGET ...]
                        Targets to seed the scan
  -w WHITELIST [WHITELIST ...], --whitelist WHITELIST [WHITELIST ...]
                        What's considered in-scope (by default it's the same as --targets)
  -b BLACKLIST [BLACKLIST ...], --blacklist BLACKLIST [BLACKLIST ...]
                        Don't touch these things
  --strict-scope        Don't consider subdomains of target/whitelist to be in-scope

Presets:
  -p [PRESET ...], --preset [PRESET ...]
                        Enable BBOT preset(s)
  -c [CONFIG ...], --config [CONFIG ...]
                        Custom config options in key=value format: e.g. 'modules.shodan.api_key=1234'
  -lp, --list-presets   List available presets.

Modules:
  -m MODULE [MODULE ...], --modules MODULE [MODULE ...]
                        Modules to enable. Choices: affiliates,ajaxpro,anubisdb,asn,azure_realm,azure_tenant,baddns,baddns_zone,badsecrets,bevigil,binaryedge,bucket_amazon,bucket_azure,bucket_digitalocean,bucket_file_enum,bucket_firebase,bucket_google,builtwith,bypass403,c99,censys,certspotter,chaos,columbus,credshed,crobat,crt,dastardly,dehashed,digitorus,dnscommonsrv,dnsdumpster,dockerhub,dotnetnuke,emailformat,ffuf,ffuf_shortnames,filedownload,fingerprintx,fullhunt,generic_ssrf,git,git_clone,github_codesearch,github_org,gitlab,gowitness,hackertarget,host_header,httpx,hunt,hunterio,iis_shortnames,internetdb,ip2location,ipneighbor,ipstack,leakix,masscan,massdns,myssl,newsletters,nmap,ntlm,nuclei,oauth,otx,paramminer_cookies,paramminer_getparams,paramminer_headers,passivetotal,pgp,postman,rapiddns,riddler,robots,secretsdb,securitytrails,shodan_dns,sitedossier,skymem,smuggler,social,sslcert,subdomaincenter,sublist3r,telerik,threatminer,trufflehog,url_manipulation,urlscan,vhost,viewdns,virustotal,wafw00f,wappalyzer,wayback,zoomeye
  -l, --list-modules    List available modules.
  -lmo, --list-module-options
                        Show all module config options
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: active,affiliates,aggressive,baddns,cloud-enum,code-enum,code-enume,deadly,email-enum,iis-shortnames,passive,portscan,report,safe,service-enum,slow,social-enum,subdomain-enum,subdomain-hijack,web-basic,web-paramminer,web-screenshots,web-thorough
  -lf, --list-flags     List available flags.
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Only enable modules with these flags (e.g. -rf passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. -ef aggressive)
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: asset_inventory,csv,discord,emails,http,human,json,neo4j,python,slack,splunk,subdomains,teams,web_report,websocket
  --allow-deadly        Enable the use of highly aggressive modules

Scan:
  -n SCAN_NAME, --name SCAN_NAME
                        Name of scan (default: random)
  -o DIR, --output-dir DIR
  -v, --verbose         Be more verbose
  -d, --debug           Enable debugging
  -s, --silent          Be quiet
  --force               Run scan even in the case of condition violations or failed module setups
  -y, --yes             Skip scan confirmation prompt
  --dry-run             Abort before executing scan
  --current-preset      Show the current preset in YAML format
  --current-preset-full
                        Show the current preset in its full form, including defaults

Module dependencies:
  Control how modules install their dependencies

  --no-deps             Don't install module dependencies
  --force-deps          Force install all module dependencies
  --retry-deps          Try again to install failed module dependencies
  --ignore-failed-deps  Run modules even if they have failed dependencies
  --install-all-deps    Install dependencies for all modules

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

    List presets:
        bbot -lp

    List flags:
        bbot -lf

```
<!-- END BBOT HELP OUTPUT -->
