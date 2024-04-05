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
               [-m MODULE [MODULE ...]] [-l] [-lmo] [-em MODULE [MODULE ...]] [-om MODULE [MODULE ...]] [-f FLAG [FLAG ...]] [-lf] [-rf FLAG [FLAG ...]] [-ef FLAG [FLAG ...]]
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
                        Modules to enable. Choices: badsecrets,urlscan,iis_shortnames,masscan,host_header,columbus,social,gitlab,riddler,bypass403,asn,generic_ssrf,postman,crobat,nmap,bucket_azure,paramminer_getparams,affiliates,github_org,dnsdumpster,builtwith,bucket_google,sublist3r,nuclei,hunterio,trufflehog,ajaxpro,ntlm,azure_realm,dotnetnuke,fullhunt,smuggler,censys,ip2location,viewdns,baddns_zone,leakix,wayback,crt,git_clone,httpx,paramminer_cookies,paramminer_headers,hunt,credshed,dnscommonsrv,sslcert,bucket_digitalocean,baddns,bucket_firebase,passivetotal,dehashed,newsletters,telerik,sitedossier,github_codesearch,ffuf,azure_tenant,hackertarget,massdns,wappalyzer,emailformat,anubisdb,gowitness,wafw00f,virustotal,binaryedge,ipstack,bucket_file_enum,certspotter,zoomeye,filedownload,docker_pull,dastardly,digitorus,internetdb,url_manipulation,securitytrails,myssl,vhost,ffuf_shortnames,dockerhub,secretsdb,threatminer,oauth,shodan_dns,chaos,robots,bevigil,otx,git,bucket_amazon,c99,rapiddns,subdomaincenter,skymem,pgp,ipneighbor,fingerprintx
  -l, --list-modules    List available modules.
  -lmo, --list-module-options
                        Show all module config options
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: csv,websocket,json,slack,teams,asset_inventory,web_report,http,neo4j,emails,subdomains,python,splunk,stdout,discord,txt
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: web-paramminer,report,active,slow,social-enum,affiliates,passive,baddns,iis-shortnames,web-screenshots,cloud-enum,web-thorough,subdomain-hijack,safe,subdomain-enum,email-enum,code-enum,portscan,service-enum,web-basic,aggressive,deadly
  -lf, --list-flags     List available flags.
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Only enable modules with these flags (e.g. -rf passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. -ef aggressive)
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
        bbot -t evilcorp.com -p subdomain-enum

    Subdomains (passive only):
        bbot -t evilcorp.com -p subdomain-enum -rf passive

    Subdomains + port scan + web screenshots:
        bbot -t evilcorp.com -p subdomain-enum -m nmap gowitness -n my_scan -o .

    Subdomains + basic web scan:
        bbot -t evilcorp.com -p subdomain-enum web-basic

    Web spider:
        bbot -t www.evilcorp.com -p spider -c web_spider_distance=2 web_spider_depth=2

    Everything everywhere all at once:
        bbot -t evilcorp.com -p kitchen-sink

    List modules:
        bbot -l

    List presets:
        bbot -lp

    List flags:
        bbot -lf

```
<!-- END BBOT HELP OUTPUT -->
