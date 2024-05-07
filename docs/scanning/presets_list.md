Below is a list of every default BBOT preset, including its YAML.

<!-- BBOT PRESET YAML -->
## **cloud-enum**

Enumerate cloud resources such as storage buckets, etc.

??? note "`cloud-enum.yml`"
    ```yaml title="~/.bbot/presets/cloud-enum.yml"
    description: Enumerate cloud resources such as storage buckets, etc.
    
    include:
      - subdomain-enum
    
    flags:
      - cloud-enum
    ```



Modules: [52]("`anubisdb`, `asn`, `azure_realm`, `azure_tenant`, `baddns_zone`, `baddns`, `bevigil`, `binaryedge`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_file_enum`, `bucket_firebase`, `bucket_google`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `columbus`, `crt`, `digitorus`, `dnscommonsrv`, `dnsdumpster`, `fullhunt`, `github_codesearch`, `github_org`, `hackertarget`, `httpx`, `hunterio`, `internetdb`, `ipneighbor`, `leakix`, `massdns`, `myssl`, `oauth`, `otx`, `passivetotal`, `postman`, `rapiddns`, `riddler`, `securitytrails`, `shodan_dns`, `sitedossier`, `social`, `sslcert`, `subdomaincenter`, `threatminer`, `urlscan`, `virustotal`, `wayback`, `zoomeye`")

## **code-enum**

Enumerate Git repositories, Docker images, etc.

??? note "`code-enum.yml`"
    ```yaml title="~/.bbot/presets/code-enum.yml"
    description: Enumerate Git repositories, Docker images, etc.
    
    flags:
      - code-enum
    ```



Modules: [9]("`dockerhub`, `git`, `github_codesearch`, `github_org`, `gitlab`, `httpx`, `postman`, `social`, `trufflehog`")

## **dirbust-heavy**

Recursive web directory brute-force (aggressive)

??? note "`dirbust-heavy.yml`"
    ```yaml title="~/.bbot/presets/web/dirbust-heavy.yml"
    description: Recursive web directory brute-force (aggressive)
    
    include:
      - spider
    
    flags:
      - iis-shortnames
    
    modules:
      - ffuf
      - wayback
    
    config:
      modules:
        iis_shortnames:
          # we exploit the shortnames vulnerability to produce URL_HINTs which are consumed by ffuf_shortnames
          detect_only: False
        ffuf:
          depth: 3
          lines: 5000
          extensions:
            - php
            - asp
            - aspx
            - ashx
            - asmx
            - jsp
            - jspx
            - cfm
            - zip
            - conf
            - config
            - xml
            - json
            - yml
            - yaml
        # emit URLs from wayback
        wayback:
          urls: True
    ```

Category: web

Modules: [5]("`ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`, `wayback`")

## **dirbust-light**

Basic web directory brute-force (surface-level directories only)

??? note "`dirbust-light.yml`"
    ```yaml title="~/.bbot/presets/web/dirbust-light.yml"
    description: Basic web directory brute-force (surface-level directories only)
    
    include:
      - iis-shortnames
    
    modules:
      - ffuf
    
    config:
      modules:
        ffuf:
          # wordlist size = 1000
          lines: 1000
    ```

Category: web

Modules: [4]("`ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`")

## **email-enum**

Enumerate email addresses from APIs, web crawling, etc.

??? note "`email-enum.yml`"
    ```yaml title="~/.bbot/presets/email-enum.yml"
    description: Enumerate email addresses from APIs, web crawling, etc.
    
    flags:
      - email-enum
    
    output_modules:
      - emails
    
    config:
      modules:
        stdout:
          format: text
          # only output EMAIL_ADDRESSes to the console
          event_types:
            - EMAIL_ADDRESS
          # only show in-scope emails
          in_scope_only: True
          # display the raw emails, nothing else
          event_fields:
            - data
          # automatically dedupe
          accept_dups: False
    ```



Modules: [6]("`dehashed`, `emailformat`, `hunterio`, `pgp`, `skymem`, `sslcert`")

## **iis-shortnames**

Recursively enumerate IIS shortnames, using ffuf to guess the remaining characters

??? note "`iis-shortnames.yml`"
    ```yaml title="~/.bbot/presets/web/iis-shortnames.yml"
    description: Recursively enumerate IIS shortnames, using ffuf to guess the remaining characters
    
    flags:
      - iis-shortnames
    
    config:
      modules:
        iis_shortnames:
          # exploit the vulnerability
          detect_only: false
    ```

Category: web

Modules: [3]("`ffuf_shortnames`, `httpx`, `iis_shortnames`")

## **kitchen-sink**

Everything everywhere all at once

??? note "`kitchen-sink.yml`"
    ```yaml title="~/.bbot/presets/kitchen-sink.yml"
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
    ```



Modules: [73]("`anubisdb`, `asn`, `azure_realm`, `azure_tenant`, `baddns_zone`, `baddns`, `badsecrets`, `bevigil`, `binaryedge`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_file_enum`, `bucket_firebase`, `bucket_google`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `columbus`, `crt`, `dehashed`, `digitorus`, `dnscommonsrv`, `dnsdumpster`, `dockerhub`, `emailformat`, `ffuf_shortnames`, `ffuf`, `filedownload`, `fullhunt`, `git`, `github_codesearch`, `github_org`, `gitlab`, `gowitness`, `hackertarget`, `httpx`, `hunterio`, `iis_shortnames`, `internetdb`, `ipneighbor`, `leakix`, `massdns`, `myssl`, `ntlm`, `oauth`, `otx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`, `passivetotal`, `pgp`, `postman`, `rapiddns`, `riddler`, `robots`, `secretsdb`, `securitytrails`, `shodan_dns`, `sitedossier`, `skymem`, `social`, `sslcert`, `subdomaincenter`, `threatminer`, `trufflehog`, `urlscan`, `virustotal`, `wappalyzer`, `wayback`, `zoomeye`")

## **paramminer**

Discover new web parameters via brute-force

??? note "`paramminer.yml`"
    ```yaml title="~/.bbot/presets/web/paramminer.yml"
    description: Discover new web parameters via brute-force
    
    flags:
      - web-paramminer
    
    modules:
      - httpx
    
    config:
      web_spider_distance: 1
      web_spider_depth: 4
    ```

Category: web

Modules: [4]("`httpx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`")

## **spider**

Recursive web spider

??? note "`spider.yml`"
    ```yaml title="~/.bbot/presets/spider.yml"
    description: Recursive web spider
    
    modules:
      - httpx
    
    config:
      # how many links to follow in a row
      web_spider_distance: 2
      # don't follow links whose directory depth is higher than 4
      web_spider_depth: 4
      # maximum number of links to follow per page
      web_spider_links_per_page: 25
    ```



Modules: [1]("`httpx`")

## **subdomain-enum**

Enumerate subdomains via APIs, brute-force

??? note "`subdomain-enum.yml`"
    ```yaml title="~/.bbot/presets/subdomain-enum.yml"
    description: Enumerate subdomains via APIs, brute-force
    
    flags:
      - subdomain-enum
    
    output_modules:
      - subdomains
    
    config_exclusive:
      custom_stdout:
        modules:
          stdout:
            format: text
            # only output DNS_NAMEs to the console
            event_types:
              - DNS_NAME
            # only show in-scope subdomains
            in_scope_only: True
            # display the raw subdomains, nothing else
            event_fields:
              - data
            # automatically dedupe
            accept_dups: False
    ```



Modules: [45]("`anubisdb`, `asn`, `azure_realm`, `azure_tenant`, `baddns_zone`, `bevigil`, `binaryedge`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `columbus`, `crt`, `digitorus`, `dnscommonsrv`, `dnsdumpster`, `fullhunt`, `github_codesearch`, `github_org`, `hackertarget`, `httpx`, `hunterio`, `internetdb`, `ipneighbor`, `leakix`, `massdns`, `myssl`, `oauth`, `otx`, `passivetotal`, `postman`, `rapiddns`, `riddler`, `securitytrails`, `shodan_dns`, `sitedossier`, `social`, `sslcert`, `subdomaincenter`, `threatminer`, `urlscan`, `virustotal`, `wayback`, `zoomeye`")

## **web-basic**

Quick web scan

??? note "`web-basic.yml`"
    ```yaml title="~/.bbot/presets/web-basic.yml"
    description: Quick web scan
    
    include:
      - iis-shortnames
    
    flags:
      - web-basic
    ```



Modules: [18]("`azure_realm`, `baddns`, `badsecrets`, `bucket_amazon`, `bucket_azure`, `bucket_firebase`, `bucket_google`, `ffuf_shortnames`, `filedownload`, `git`, `httpx`, `iis_shortnames`, `ntlm`, `oauth`, `robots`, `secretsdb`, `sslcert`, `wappalyzer`")

## **web-screenshots**

Take screenshots of webpages

??? note "`web-screenshots.yml`"
    ```yaml title="~/.bbot/presets/web-screenshots.yml"
    description: Take screenshots of webpages
    
    flags:
      - web-screenshots
    
    config:
      modules:
        gowitness:
          resolution_x: 1440
          resolution_y: 900
          # folder to output web screenshots (default is inside ~/.bbot/scans/scan_name)
          output_path: ""
          # whether to take screenshots of social media pages
          social: True
    ```



Modules: [3]("`gowitness`, `httpx`, `social`")

## **web-thorough**

Aggressive web scan

??? note "`web-thorough.yml`"
    ```yaml title="~/.bbot/presets/web-thorough.yml"
    description: Aggressive web scan
    
    include:
      - web-basic
    
    flags:
      - web-thorough
    ```



Modules: [30]("`ajaxpro`, `azure_realm`, `baddns`, `badsecrets`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_firebase`, `bucket_google`, `bypass403`, `dastardly`, `dotnetnuke`, `ffuf_shortnames`, `filedownload`, `generic_ssrf`, `git`, `host_header`, `httpx`, `hunt`, `iis_shortnames`, `nmap`, `ntlm`, `oauth`, `robots`, `secretsdb`, `smuggler`, `sslcert`, `telerik`, `url_manipulation`, `wappalyzer`")
<!-- END BBOT PRESET YAML -->

## Table of Default Presets

Here is a the same data, but in a table:

<!-- BBOT PRESETS -->
| Preset          | Category   | Description                                                                        | # Modules   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|-----------------|------------|------------------------------------------------------------------------------------|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| cloud-enum      |            | Enumerate cloud resources such as storage buckets, etc.                            | 52          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_zone, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                        |
| code-enum       |            | Enumerate Git repositories, Docker images, etc.                                    | 9           | dockerhub, git, github_codesearch, github_org, gitlab, httpx, postman, social, trufflehog                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| dirbust-heavy   | web        | Recursive web directory brute-force (aggressive)                                   | 5           | ffuf, ffuf_shortnames, httpx, iis_shortnames, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| dirbust-light   | web        | Basic web directory brute-force (surface-level directories only)                   | 4           | ffuf, ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| email-enum      |            | Enumerate email addresses from APIs, web crawling, etc.                            | 6           | dehashed, emailformat, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| iis-shortnames  | web        | Recursively enumerate IIS shortnames, using ffuf to guess the remaining characters | 3           | ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| kitchen-sink    |            | Everything everywhere all at once                                                  | 73          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_zone, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, dockerhub, emailformat, ffuf, ffuf_shortnames, filedownload, fullhunt, git, github_codesearch, github_org, gitlab, gowitness, hackertarget, httpx, hunterio, iis_shortnames, internetdb, ipneighbor, leakix, massdns, myssl, ntlm, oauth, otx, paramminer_cookies, paramminer_getparams, paramminer_headers, passivetotal, pgp, postman, rapiddns, riddler, robots, secretsdb, securitytrails, shodan_dns, sitedossier, skymem, social, sslcert, subdomaincenter, threatminer, trufflehog, urlscan, virustotal, wappalyzer, wayback, zoomeye |
| paramminer      | web        | Discover new web parameters via brute-force                                        | 4           | httpx, paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| spider          |            | Recursive web spider                                                               | 1           | httpx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| subdomain-enum  |            | Enumerate subdomains via APIs, brute-force                                         | 45          | anubisdb, asn, azure_realm, azure_tenant, baddns_zone, bevigil, binaryedge, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                                                    |
| web-basic       |            | Quick web scan                                                                     | 18          | azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, ffuf_shortnames, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, secretsdb, sslcert, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| web-screenshots |            | Take screenshots of webpages                                                       | 3           | gowitness, httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| web-thorough    |            | Aggressive web scan                                                                | 30          | ajaxpro, azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dotnetnuke, ffuf_shortnames, filedownload, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, nmap, ntlm, oauth, robots, secretsdb, smuggler, sslcert, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
<!-- END BBOT PRESETS -->
