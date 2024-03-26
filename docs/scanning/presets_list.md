Below is a list of every default BBOT preset, including its YAML.

<!-- BBOT PRESET YAML -->
## **cloud-enum**

Enumerate cloud resources such as storage buckets, etc.

??? note "`cloud-enum.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/cloud-enum.yml"
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
    ```yaml title="~/Downloads/code/bbot/bbot/presets/code-enum.yml"
    description: Enumerate Git repositories, Docker images, etc.
    
    flags:
      - code-enum
    ```



Modules: [6]("`dockerhub`, `github_codesearch`, `github_org`, `gitlab`, `httpx`, `social`")

## **dirbust-heavy**

Recursive web directory brute-force (aggressive)

??? note "`dirbust-heavy.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/web_advanced/dirbust-heavy.yml"
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

Category: web_advanced

Modules: [5]("`ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`, `wayback`")

## **dirbust-light**

Basic web directory brute-force (surface-level directories only)

??? note "`dirbust-light.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/web_advanced/dirbust-light.yml"
    description: Basic web directory brute-force (surface-level directories only)
    
    flags:
      - iis-shortnames
    
    modules:
      - ffuf
    
    config:
      modules:
        iis_shortnames:
          # we exploit the shortnames vulnerability to produce URL_HINTs which are consumed by ffuf_shortnames
          detect_only: False
        ffuf:
          # wordlist size = 1000
          lines: 1000
    ```

Category: web_advanced

Modules: [4]("`ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`")

## **email-enum**

Enumerate email addresses from APIs, web crawling, etc.

??? note "`email-enum.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/email-enum.yml"
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

## **kitchen-sink**

Everything everywhere all at once

??? note "`kitchen-sink.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/kitchen-sink.yml"
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
    ```



Modules: [71]("`anubisdb`, `asn`, `azure_realm`, `azure_tenant`, `baddns_zone`, `baddns`, `badsecrets`, `bevigil`, `binaryedge`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_file_enum`, `bucket_firebase`, `bucket_google`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `columbus`, `crt`, `dehashed`, `digitorus`, `dnscommonsrv`, `dnsdumpster`, `dockerhub`, `emailformat`, `ffuf_shortnames`, `ffuf`, `filedownload`, `fullhunt`, `git`, `github_codesearch`, `github_org`, `gitlab`, `hackertarget`, `httpx`, `hunterio`, `iis_shortnames`, `internetdb`, `ipneighbor`, `leakix`, `massdns`, `myssl`, `ntlm`, `oauth`, `otx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`, `passivetotal`, `pgp`, `postman`, `rapiddns`, `riddler`, `robots`, `secretsdb`, `securitytrails`, `shodan_dns`, `sitedossier`, `skymem`, `social`, `sslcert`, `subdomaincenter`, `threatminer`, `urlscan`, `virustotal`, `wappalyzer`, `wayback`, `zoomeye`")

## **paramminer**

Discover new web parameters via brute-force

??? note "`paramminer.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/web_advanced/paramminer.yml"
    description: Discover new web parameters via brute-force
    
    flags:
      - web-paramminer
    
    modules:
      - httpx
    
    config:
      web_spider_distance: 1
      web_spider_depth: 4
    ```

Category: web_advanced

Modules: [4]("`httpx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`")

## **secrets-enum**



??? note "`secrets-enum.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/secrets-enum.yml"
    description: 
    ```



Modules: [0]("")

## **spider**

Recursive web spider

??? note "`spider.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/spider.yml"
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
    
      modules:
        stdout:
          format: text
          # only output URLs to the console
          event_types:
            - URL
          # only show in-scope URLs
          in_scope_only: True
          # display the raw URLs, nothing else
          event_fields:
            - data
          # automatically dedupe
          accept_dups: False
    ```



Modules: [1]("`httpx`")

## **subdomain-enum**

Enumerate subdomains via APIs, brute-force

??? note "`subdomain-enum.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/subdomain-enum.yml"
    description: Enumerate subdomains via APIs, brute-force
    
    flags:
      - subdomain-enum
    
    output_modules:
      - subdomains
    
    config:
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
    ```yaml title="~/Downloads/code/bbot/bbot/presets/web-basic.yml"
    description: Quick web scan
    
    flags:
      - web-basic
    ```



Modules: [17]("`azure_realm`, `baddns`, `badsecrets`, `bucket_amazon`, `bucket_azure`, `bucket_firebase`, `bucket_google`, `filedownload`, `git`, `httpx`, `iis_shortnames`, `ntlm`, `oauth`, `robots`, `secretsdb`, `sslcert`, `wappalyzer`")

## **web-thorough**

Aggressive web scan

??? note "`web-thorough.yml`"
    ```yaml title="~/Downloads/code/bbot/bbot/presets/web-thorough.yml"
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
| Preset         | Category     | Description                                                      | # Modules   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|----------------|--------------|------------------------------------------------------------------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| cloud-enum     |              | Enumerate cloud resources such as storage buckets, etc.          | 52          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_zone, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                 |
| code-enum      |              | Enumerate Git repositories, Docker images, etc.                  | 6           | dockerhub, github_codesearch, github_org, gitlab, httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| dirbust-heavy  | web_advanced | Recursive web directory brute-force (aggressive)                 | 5           | ffuf, ffuf_shortnames, httpx, iis_shortnames, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| dirbust-light  | web_advanced | Basic web directory brute-force (surface-level directories only) | 4           | ffuf, ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| email-enum     |              | Enumerate email addresses from APIs, web crawling, etc.          | 6           | dehashed, emailformat, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| kitchen-sink   |              | Everything everywhere all at once                                | 71          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_zone, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, dockerhub, emailformat, ffuf, ffuf_shortnames, filedownload, fullhunt, git, github_codesearch, github_org, gitlab, hackertarget, httpx, hunterio, iis_shortnames, internetdb, ipneighbor, leakix, massdns, myssl, ntlm, oauth, otx, paramminer_cookies, paramminer_getparams, paramminer_headers, passivetotal, pgp, postman, rapiddns, riddler, robots, secretsdb, securitytrails, shodan_dns, sitedossier, skymem, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wappalyzer, wayback, zoomeye |
| paramminer     | web_advanced | Discover new web parameters via brute-force                      | 4           | httpx, paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| secrets-enum   |              |                                                                  | 0           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| spider         |              | Recursive web spider                                             | 1           | httpx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| subdomain-enum |              | Enumerate subdomains via APIs, brute-force                       | 45          | anubisdb, asn, azure_realm, azure_tenant, baddns_zone, bevigil, binaryedge, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                             |
| web-basic      |              | Quick web scan                                                   | 17          | azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, secretsdb, sslcert, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| web-thorough   |              | Aggressive web scan                                              | 30          | ajaxpro, azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dotnetnuke, ffuf_shortnames, filedownload, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, nmap, ntlm, oauth, robots, secretsdb, smuggler, sslcert, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
<!-- END BBOT PRESETS -->
