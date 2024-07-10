# Advanced

Below you can find some advanced uses of BBOT.

## BBOT as a Python library

**Synchronous**

```python
from bbot.scanner import Scanner

# any number of targets can be specified
scan = Scanner("example.com", "scanme.nmap.org", modules=["portscan", "sslcert"])
for event in scan.start():
    print(event.json())
```

**Asynchronous**

```python
from bbot.scanner import Scanner

async def main():
    scan = Scanner("example.com", "scanme.nmap.org", modules=["portscan", "sslcert"])
    async for event in scan.async_start():
        print(event.json())

import asyncio
asyncio.run(main())
```

## Command-Line Help

<!-- BBOT HELP OUTPUT -->
```text
usage: bbot [-h] [-t TARGET [TARGET ...]] [-w WHITELIST [WHITELIST ...]]
               [-b BLACKLIST [BLACKLIST ...]] [--strict-scope]
               [-p [PRESET ...]] [-c [CONFIG ...]] [-lp]
               [-m MODULE [MODULE ...]] [-l] [-lmo] [-em MODULE [MODULE ...]]
               [-f FLAG [FLAG ...]] [-lf] [-rf FLAG [FLAG ...]]
               [-ef FLAG [FLAG ...]] [--allow-deadly] [-n SCAN_NAME] [-v] [-d]
               [-s] [--force] [-y] [--dry-run] [--current-preset]
               [--current-preset-full] [-o DIR] [-om MODULE [MODULE ...]]
               [--json] [--brief]
               [--event-types EVENT_TYPES [EVENT_TYPES ...]]
               [--no-deps | --force-deps | --retry-deps | --ignore-failed-deps | --install-all-deps]
               [--version] [-H CUSTOM_HEADERS [CUSTOM_HEADERS ...]]
               [--custom-yara-rules CUSTOM_YARA_RULES]

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
                        Modules to enable. Choices: dockerhub,iis_shortnames,shodan_dns,git_clone,wappalyzer,bucket_file_enum,baddns_zone,dastardly,gowitness,hunterio,paramminer_headers,bevigil,telerik,dotnetnuke,anubisdb,paramminer_cookies,newsletters,viewdns,bucket_google,github_codesearch,gitlab,dnscaa,fingerprintx,ntlm,securitytrails,chaos,smuggler,riddler,ffuf_shortnames,ajaxpro,wayback,dnsbrute_mutations,sublist3r,bypass403,passivetotal,bucket_azure,vhost,zoomeye,dnsdumpster,subdomaincenter,postman,baddns,affiliates,httpx,internetdb,azure_tenant,threatminer,github_org,github_workflows,dehashed,pgp,ip2location,badsecrets,ffuf,secretsdb,crobat,wafw00f,certspotter,fullhunt,urlscan,otx,bucket_firebase,nuclei,portscan,code_repository,crt,sitedossier,docker_pull,dnscommonsrv,git,ipneighbor,columbus,robots,host_header,asn,bucket_amazon,digitorus,trufflehog,builtwith,hunt,hackertarget,azure_realm,oauth,leakix,filedownload,censys,skymem,unstructured,dnsbrute,generic_ssrf,binaryedge,sslcert,rapiddns,wpscan,myssl,credshed,emailformat,bucket_digitalocean,social,virustotal,c99,paramminer_getparams,url_manipulation,ipstack
  -l, --list-modules    List available modules.
  -lmo, --list-module-options
                        Show all module config options
  -em MODULE [MODULE ...], --exclude-modules MODULE [MODULE ...]
                        Exclude these modules.
  -f FLAG [FLAG ...], --flags FLAG [FLAG ...]
                        Enable modules by flag. Choices: active,social-enum,service-enum,passive,email-enum,web-thorough,subdomain-hijack,web-screenshots,web-paramminer,iis-shortnames,slow,cloud-enum,portscan,baddns,affiliates,safe,code-enum,subdomain-enum,web-basic,aggressive,deadly,report
  -lf, --list-flags     List available flags.
  -rf FLAG [FLAG ...], --require-flags FLAG [FLAG ...]
                        Only enable modules with these flags (e.g. -rf passive)
  -ef FLAG [FLAG ...], --exclude-flags FLAG [FLAG ...]
                        Disable modules with these flags. (e.g. -ef aggressive)
  --allow-deadly        Enable the use of highly aggressive modules

Scan:
  -n SCAN_NAME, --name SCAN_NAME
                        Name of scan (default: random)
  -v, --verbose         Be more verbose
  -d, --debug           Enable debugging
  -s, --silent          Be quiet
  --force               Run scan even in the case of condition violations or failed module setups
  -y, --yes             Skip scan confirmation prompt
  --dry-run             Abort before executing scan
  --current-preset      Show the current preset in YAML format
  --current-preset-full
                        Show the current preset in its full form, including defaults

Output:
  -o DIR, --output-dir DIR
                        Directory to output scan results
  -om MODULE [MODULE ...], --output-modules MODULE [MODULE ...]
                        Output module(s). Choices: python,stdout,http,asset_inventory,txt,subdomains,emails,websocket,discord,neo4j,slack,web_report,csv,json,teams,splunk
  --json, -j            Output scan data in JSON format
  --brief, -br          Output only the data itself
  --event-types EVENT_TYPES [EVENT_TYPES ...]
                        Choose which event types to display

Module dependencies:
  Control how modules install their dependencies

  --no-deps             Don't install module dependencies
  --force-deps          Force install all module dependencies
  --retry-deps          Try again to install failed module dependencies
  --ignore-failed-deps  Run modules even if they have failed dependencies
  --install-all-deps    Install dependencies for all modules

Misc:
  --version             show BBOT version and exit
  -H CUSTOM_HEADERS [CUSTOM_HEADERS ...], --custom-headers CUSTOM_HEADERS [CUSTOM_HEADERS ...]
                        List of custom headers as key value pairs (header=value).
  --custom-yara-rules CUSTOM_YARA_RULES, -cy CUSTOM_YARA_RULES
                        Add custom yara rules to excavate

EXAMPLES

    Subdomains:
        bbot -t evilcorp.com -p subdomain-enum

    Subdomains (passive only):
        bbot -t evilcorp.com -p subdomain-enum -rf passive

    Subdomains + port scan + web screenshots:
        bbot -t evilcorp.com -p subdomain-enum -m portscan gowitness -n my_scan -o .

    Subdomains + basic web scan:
        bbot -t evilcorp.com -p subdomain-enum web-basic

    Web spider:
        bbot -t www.evilcorp.com -p spider -c web.spider_distance=2 web.spider_depth=2

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
