Below is a list of every default BBOT preset, including its YAML.

<!-- BBOT PRESET YAML -->
## **baddns-intense**

Run all baddns modules and submodules.

??? note "`baddns-intense.yml`"
    ```yaml title="~/.bbot/presets/baddns-intense.yml"
    description: Run all baddns modules and submodules.
    
    
    modules:
      - baddns
      - baddns_zone
      - baddns_direct
    
    config:
      modules:
        baddns:
          enabled_submodules: [CNAME,references,MX,NS,TXT]
    ```



Modules: [4]("`baddns_direct`, `baddns_zone`, `baddns`, `httpx`")

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



Modules: [59]("`anubisdb`, `asn`, `azure_realm`, `azure_tenant`, `baddns_direct`, `baddns_zone`, `baddns`, `bevigil`, `binaryedge`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_file_enum`, `bucket_firebase`, `bucket_google`, `bufferoverrun`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `crt`, `digitorus`, `dnsbimi`, `dnsbrute_mutations`, `dnsbrute`, `dnscaa`, `dnscommonsrv`, `dnsdumpster`, `dnstlsrpt`, `fullhunt`, `github_codesearch`, `github_org`, `hackertarget`, `httpx`, `hunterio`, `internetdb`, `ipneighbor`, `leakix`, `myssl`, `oauth`, `otx`, `passivetotal`, `postman_download`, `postman`, `rapiddns`, `securitytrails`, `securitytxt`, `shodan_dns`, `sitedossier`, `social`, `sslcert`, `subdomaincenter`, `subdomainradar`, `trickest`, `urlscan`, `virustotal`, `wayback`, `zoomeye`")

## **code-enum**

Enumerate Git repositories, Docker images, etc.

??? note "`code-enum.yml`"
    ```yaml title="~/.bbot/presets/code-enum.yml"
    description: Enumerate Git repositories, Docker images, etc.
    
    flags:
      - code-enum
    ```



Modules: [18]("`apkpure`, `code_repository`, `docker_pull`, `dockerhub`, `git_clone`, `git`, `gitdumper`, `github_codesearch`, `github_org`, `github_workflows`, `gitlab`, `google_playstore`, `httpx`, `jadx`, `postman_download`, `postman`, `social`, `trufflehog`")

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

## **dirbust-heavy**

Recursive web directory brute-force (aggressive)

??? note "`dirbust-heavy.yml`"
    ```yaml title="~/.bbot/presets/dirbust-heavy.yml"
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

## **dirbust-light**

Basic web directory brute-force (surface-level directories only)

??? note "`dirbust-light.yml`"
    ```yaml title="~/.bbot/presets/dirbust-light.yml"
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



Modules: [4]("`ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`")

## **dotnet-audit**

Comprehensive scan for all IIS/.NET specific modules and module settings

??? note "`dotnet-audit.yml`"
    ```yaml title="~/.bbot/presets/web/dotnet-audit.yml"
    description: Comprehensive scan for all IIS/.NET specific modules and module settings
    
    
    include:
      - iis-shortnames
    
    modules:
      - httpx
      - badsecrets
      - ffuf_shortnames
      - ffuf
      - telerik
      - ajaxpro
      - dotnetnuke
    
    config:
      modules:
        ffuf:
          extensions: asp,aspx,ashx,asmx,ascx
          extensions_ignore_case: True
        ffuf_shortnames:
          find_subwords: True
        telerik:
          exploit_RAU_crypto: True
          include_subdirs: True # Run against every directory, not the default first received URL per-host
    ```

Category: web

Modules: [8]("`ajaxpro`, `badsecrets`, `dotnetnuke`, `ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`, `telerik`")

## **dotnet-audit**

Comprehensive scan for all IIS/.NET specific modules and module settings

??? note "`dotnet-audit.yml`"
    ```yaml title="~/.bbot/presets/dotnet-audit.yml"
    description: Comprehensive scan for all IIS/.NET specific modules and module settings
    
    
    include:
      - iis-shortnames
    
    modules:
      - httpx
      - badsecrets
      - ffuf_shortnames
      - ffuf
      - telerik
      - ajaxpro
      - dotnetnuke
    
    config:
      modules:
        ffuf:
          extensions: asp,aspx,ashx,asmx,ascx
          extensions_ignore_case: True
        ffuf_shortnames:
          find_subwords: True
        telerik:
          exploit_RAU_crypto: True
          include_subdirs: True # Run against every directory, not the default first received URL per-host
    ```



Modules: [8]("`ajaxpro`, `badsecrets`, `dotnetnuke`, `ffuf_shortnames`, `ffuf`, `httpx`, `iis_shortnames`, `telerik`")

## **email-enum**

Enumerate email addresses from APIs, web crawling, etc.

??? note "`email-enum.yml`"
    ```yaml title="~/.bbot/presets/email-enum.yml"
    description: Enumerate email addresses from APIs, web crawling, etc.
    
    flags:
      - email-enum
    
    output_modules:
      - emails
    ```



Modules: [8]("`dehashed`, `dnscaa`, `dnstlsrpt`, `emailformat`, `hunterio`, `pgp`, `skymem`, `sslcert`")

## **fast**

Scan only the provided targets as fast as possible - no extra discovery

??? note "`fast.yml`"
    ```yaml title="~/.bbot/presets/fast.yml"
    description: Scan only the provided targets as fast as possible - no extra discovery
    
    exclude_modules:
      - excavate
    
    config:
      # only scan the exact targets specified
      scope:
        strict: true
      # speed up dns resolution by doing A/AAAA only - not MX/NS/SRV/etc
      dns:
        minimal: true
      # essential speculation only
      modules:
        speculate:
          essential_only: true
    ```



Modules: [0]("")

## **iis-shortnames**

Recursively enumerate IIS shortnames

??? note "`iis-shortnames.yml`"
    ```yaml title="~/.bbot/presets/web/iis-shortnames.yml"
    description: Recursively enumerate IIS shortnames
    
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

## **iis-shortnames**

Recursively enumerate IIS shortnames

??? note "`iis-shortnames.yml`"
    ```yaml title="~/.bbot/presets/iis-shortnames.yml"
    description: Recursively enumerate IIS shortnames
    
    flags:
      - iis-shortnames
    
    config:
      modules:
        iis_shortnames:
          # exploit the vulnerability
          detect_only: false
    ```



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
      - baddns-intense
    
    config:
      modules:
        baddns:
          enable_references: True
    ```



Modules: [87]("`anubisdb`, `apkpure`, `asn`, `azure_realm`, `azure_tenant`, `baddns_direct`, `baddns_zone`, `baddns`, `badsecrets`, `bevigil`, `binaryedge`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_file_enum`, `bucket_firebase`, `bucket_google`, `bufferoverrun`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `code_repository`, `crt`, `dehashed`, `digitorus`, `dnsbimi`, `dnsbrute_mutations`, `dnsbrute`, `dnscaa`, `dnscommonsrv`, `dnsdumpster`, `dnstlsrpt`, `docker_pull`, `dockerhub`, `emailformat`, `ffuf_shortnames`, `ffuf`, `filedownload`, `fullhunt`, `git_clone`, `git`, `gitdumper`, `github_codesearch`, `github_org`, `github_workflows`, `gitlab`, `google_playstore`, `gowitness`, `hackertarget`, `httpx`, `hunterio`, `iis_shortnames`, `internetdb`, `ipneighbor`, `jadx`, `leakix`, `myssl`, `ntlm`, `oauth`, `otx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`, `passivetotal`, `pgp`, `postman_download`, `postman`, `rapiddns`, `robots`, `securitytrails`, `securitytxt`, `shodan_dns`, `sitedossier`, `skymem`, `social`, `sslcert`, `subdomaincenter`, `subdomainradar`, `trickest`, `trufflehog`, `urlscan`, `virustotal`, `wappalyzer`, `wayback`, `zoomeye`")

## **nuclei**

Run nuclei scans against all discovered targets

??? note "`nuclei.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei.yml"
    description: Run nuclei scans against all discovered targets
    
    modules:
      - httpx
      - nuclei
      - portfilter
    
    config:
      modules:
        nuclei:
          directory_only: True # Do not run nuclei on individual non-directory URLs
    
    
    conditions:
      - |
        {% if config.web.spider_distance != 0 %}
          {{ warn("Running nuclei with spider enabled is generally not recommended. Consider removing 'spider' preset.") }}
        {% endif %}
    
    
    
    # Additional Examples:
    
    # Slowing Down Scan
    
    #config:
    #  modules:
    #    nuclei:
    #      ratelimit: 10
    #      concurrency: 5
    
    
    
    
    ```

Category: nuclei

Modules: [3]("`httpx`, `nuclei`, `portfilter`")

## **nuclei**

Run nuclei scans against all discovered targets

??? note "`nuclei.yml`"
    ```yaml title="~/.bbot/presets/nuclei.yml"
    description: Run nuclei scans against all discovered targets
    
    modules:
      - httpx
      - nuclei
      - portfilter
    
    config:
      modules:
        nuclei:
          directory_only: True # Do not run nuclei on individual non-directory URLs
    
    
    conditions:
      - |
        {% if config.web.spider_distance != 0 %}
          {{ warn("Running nuclei with spider enabled is generally not recommended. Consider removing 'spider' preset.") }}
        {% endif %}
    
    
    
    # Additional Examples:
    
    # Slowing Down Scan
    
    #config:
    #  modules:
    #    nuclei:
    #      ratelimit: 10
    #      concurrency: 5
    
    
    
    
    ```



Modules: [3]("`httpx`, `nuclei`, `portfilter`")

## **nuclei-budget**

Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests

??? note "`nuclei-budget.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei-budget.yml"
    description: Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests
    
    modules:
      - httpx
      - nuclei
      - portfilter
    
    config:
      modules:
        nuclei:
          mode: budget
          budget: 10
          directory_only: true # Do not run nuclei on individual non-directory URLs
    
    conditions:
      - |
        {% if config.web.spider_distance != 0 %}
          {{ warn("Running nuclei with spider enabled is generally not recommended. Consider removing 'spider' preset.") }}
        {% endif %}
    ```

Category: nuclei

Modules: [3]("`httpx`, `nuclei`, `portfilter`")

## **nuclei-budget**

Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests

??? note "`nuclei-budget.yml`"
    ```yaml title="~/.bbot/presets/nuclei-budget.yml"
    description: Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests
    
    modules:
      - httpx
      - nuclei
      - portfilter
    
    config:
      modules:
        nuclei:
          mode: budget
          budget: 10
          directory_only: true # Do not run nuclei on individual non-directory URLs
    
    conditions:
      - |
        {% if config.web.spider_distance != 0 %}
          {{ warn("Running nuclei with spider enabled is generally not recommended. Consider removing 'spider' preset.") }}
        {% endif %}
    ```



Modules: [3]("`httpx`, `nuclei`, `portfilter`")

## **nuclei-intense**

Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.

??? note "`nuclei-intense.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei-intense.yml"
    description: Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.
    
    modules:
      - httpx
      - nuclei
      - robots
      - urlscan
      - portfilter
      - wayback
    
    config:
      modules:
        nuclei:
          directory_only: False # Will run nuclei on ALL discovered URLs - Be careful!
        wayback:
          urls: true
    
    conditions:
      - |
        {% if config.web.spider_distance == 0 and config.modules.nuclei.directory_only == False %}
          {{ warn("The 'nuclei-intense' preset turns the 'directory_only' limitation off on the nuclei module. To make the best use of this, you may want to enable spidering with 'spider' or 'spider-intense' preset.") }}
        {% endif %}
    
    
    # Example for also running a dirbust
    
    #include:
    #  - dirbust-light
    ```

Category: nuclei

Modules: [6]("`httpx`, `nuclei`, `portfilter`, `robots`, `urlscan`, `wayback`")

## **nuclei-intense**

Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.

??? note "`nuclei-intense.yml`"
    ```yaml title="~/.bbot/presets/nuclei-intense.yml"
    description: Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.
    
    modules:
      - httpx
      - nuclei
      - robots
      - urlscan
      - portfilter
      - wayback
    
    config:
      modules:
        nuclei:
          directory_only: False # Will run nuclei on ALL discovered URLs - Be careful!
        wayback:
          urls: true
    
    conditions:
      - |
        {% if config.web.spider_distance == 0 and config.modules.nuclei.directory_only == False %}
          {{ warn("The 'nuclei-intense' preset turns the 'directory_only' limitation off on the nuclei module. To make the best use of this, you may want to enable spidering with 'spider' or 'spider-intense' preset.") }}
        {% endif %}
    
    
    # Example for also running a dirbust
    
    #include:
    #  - dirbust-light
    ```



Modules: [6]("`httpx`, `nuclei`, `portfilter`, `robots`, `urlscan`, `wayback`")

## **nuclei-technology**

Run nuclei scans against all discovered targets, running templates which match discovered technologies

??? note "`nuclei-technology.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei-technology.yml"
    description: Run nuclei scans against all discovered targets, running templates which match discovered technologies
    
    modules:
      - httpx
      - nuclei
      - portfilter
    
    config:
      modules:
        nuclei:
          mode: technology
          directory_only: True # Do not run nuclei on individual non-directory URLs. This is less unsafe to disable with technology mode.
    
    conditions:
      - |
        {% if config.web.spider_distance != 0 %}
          {{ warn("Running nuclei with spider enabled is generally not recommended. Consider removing 'spider' preset.") }}
        {% endif %}
    
    # Example for also running a dirbust
    
    #include:
    #  - dirbust-light
    ```

Category: nuclei

Modules: [3]("`httpx`, `nuclei`, `portfilter`")

## **nuclei-technology**

Run nuclei scans against all discovered targets, running templates which match discovered technologies

??? note "`nuclei-technology.yml`"
    ```yaml title="~/.bbot/presets/nuclei-technology.yml"
    description: Run nuclei scans against all discovered targets, running templates which match discovered technologies
    
    modules:
      - httpx
      - nuclei
      - portfilter
    
    config:
      modules:
        nuclei:
          mode: technology
          directory_only: True # Do not run nuclei on individual non-directory URLs. This is less unsafe to disable with technology mode.
    
    conditions:
      - |
        {% if config.web.spider_distance != 0 %}
          {{ warn("Running nuclei with spider enabled is generally not recommended. Consider removing 'spider' preset.") }}
        {% endif %}
    
    # Example for also running a dirbust
    
    #include:
    #  - dirbust-light
    ```



Modules: [3]("`httpx`, `nuclei`, `portfilter`")

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
      web:
        spider_distance: 1
        spider_depth: 4
    ```

Category: web

Modules: [4]("`httpx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`")

## **paramminer**

Discover new web parameters via brute-force

??? note "`paramminer.yml`"
    ```yaml title="~/.bbot/presets/paramminer.yml"
    description: Discover new web parameters via brute-force
    
    flags:
      - web-paramminer
    
    modules:
      - httpx
    
    config:
      web:
        spider_distance: 1
        spider_depth: 4
    ```



Modules: [4]("`httpx`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`")

## **spider**

Recursive web spider

??? note "`spider.yml`"
    ```yaml title="~/.bbot/presets/spider.yml"
    description: Recursive web spider
    
    modules:
      - httpx
    
    blacklist:
      # Prevent spider from invalidating sessions by logging out
      - "RE:/.*(sign|log)[_-]?out"
    
    config:
      web:
        # how many links to follow in a row
        spider_distance: 2
        # don't follow links whose directory depth is higher than 4
        spider_depth: 4
        # maximum number of links to follow per page
        spider_links_per_page: 25
    ```



Modules: [1]("`httpx`")

## **spider-intense**

Recursive web spider with more aggressive settings

??? note "`spider-intense.yml`"
    ```yaml title="~/.bbot/presets/spider-intense.yml"
    description: Recursive web spider with more aggressive settings
    
    include:
      - spider
      
    config:
      web:
        # how many links to follow in a row
        spider_distance: 4
        # don't follow links whose directory depth is higher than 6
        spider_depth: 6
        # maximum number of links to follow per page
        spider_links_per_page: 50
    ```



Modules: [1]("`httpx`")

## **subdomain-enum**

Enumerate subdomains via APIs, brute-force

??? note "`subdomain-enum.yml`"
    ```yaml title="~/.bbot/presets/subdomain-enum.yml"
    description: Enumerate subdomains via APIs, brute-force
    
    flags:
      # enable every module with the subdomain-enum flag
      - subdomain-enum
    
    output_modules:
      # output unique subdomains to TXT file
      - subdomains
    
    config:
      dns:
        threads: 25
        brute_threads: 1000
      # put your API keys here
      # modules:
      #   github:
      #     api_key: ""
      #   chaos:
      #     api_key: ""
      #   securitytrails:
      #     api_key: ""
    ```



Modules: [52]("`anubisdb`, `asn`, `azure_realm`, `azure_tenant`, `baddns_direct`, `baddns_zone`, `bevigil`, `binaryedge`, `bufferoverrun`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `crt`, `digitorus`, `dnsbimi`, `dnsbrute_mutations`, `dnsbrute`, `dnscaa`, `dnscommonsrv`, `dnsdumpster`, `dnstlsrpt`, `fullhunt`, `github_codesearch`, `github_org`, `hackertarget`, `httpx`, `hunterio`, `internetdb`, `ipneighbor`, `leakix`, `myssl`, `oauth`, `otx`, `passivetotal`, `postman_download`, `postman`, `rapiddns`, `securitytrails`, `securitytxt`, `shodan_dns`, `sitedossier`, `social`, `sslcert`, `subdomaincenter`, `subdomainradar`, `trickest`, `urlscan`, `virustotal`, `wayback`, `zoomeye`")

## **tech-detect**

Detect technologies via Wappalyzer, Nuclei, and FingerprintX

??? note "`tech-detect.yml`"
    ```yaml title="~/.bbot/presets/tech-detect.yml"
    description: Detect technologies via Wappalyzer, Nuclei, and FingerprintX
    
    modules:
      - nuclei
      - wappalyzer
      - fingerprintx
    
    config:
      modules:
        nuclei:
          tags: tech
    ```



Modules: [4]("`fingerprintx`, `httpx`, `nuclei`, `wappalyzer`")

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



Modules: [18]("`azure_realm`, `baddns`, `badsecrets`, `bucket_amazon`, `bucket_azure`, `bucket_firebase`, `bucket_google`, `ffuf_shortnames`, `filedownload`, `git`, `httpx`, `iis_shortnames`, `ntlm`, `oauth`, `robots`, `securitytxt`, `sslcert`, `wappalyzer`")

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
      # include the web-basic preset
      - web-basic
    
    flags:
      - web-thorough
    ```



Modules: [29]("`ajaxpro`, `azure_realm`, `baddns`, `badsecrets`, `bucket_amazon`, `bucket_azure`, `bucket_digitalocean`, `bucket_firebase`, `bucket_google`, `bypass403`, `dastardly`, `dotnetnuke`, `ffuf_shortnames`, `filedownload`, `generic_ssrf`, `git`, `host_header`, `httpx`, `hunt`, `iis_shortnames`, `ntlm`, `oauth`, `robots`, `securitytxt`, `smuggler`, `sslcert`, `telerik`, `url_manipulation`, `wappalyzer`")
<!-- END BBOT PRESET YAML -->

## Table of Default Presets

Here is a the same data, but in a table:

<!-- BBOT PRESETS -->
| Preset            | Category   | Description                                                                                                                              | # Modules   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|-------------------|------------|------------------------------------------------------------------------------------------------------------------------------------------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| baddns-intense    |            | Run all baddns modules and submodules.                                                                                                   | 4           | baddns, baddns_direct, baddns_zone, httpx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| cloud-enum        |            | Enumerate cloud resources such as storage buckets, etc.                                                                                  | 59          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_direct, baddns_zone, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, bufferoverrun, builtwith, c99, censys, certspotter, chaos, crt, digitorus, dnsbimi, dnsbrute, dnsbrute_mutations, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, myssl, oauth, otx, passivetotal, postman, postman_download, rapiddns, securitytrails, securitytxt, shodan_dns, sitedossier, social, sslcert, subdomaincenter, subdomainradar, trickest, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                                    |
| code-enum         |            | Enumerate Git repositories, Docker images, etc.                                                                                          | 18          | apkpure, code_repository, docker_pull, dockerhub, git, git_clone, gitdumper, github_codesearch, github_org, github_workflows, gitlab, google_playstore, httpx, jadx, postman, postman_download, social, trufflehog                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| dirbust-heavy     | web        | Recursive web directory brute-force (aggressive)                                                                                         | 5           | ffuf, ffuf_shortnames, httpx, iis_shortnames, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| dirbust-heavy     |            | Recursive web directory brute-force (aggressive)                                                                                         | 5           | ffuf, ffuf_shortnames, httpx, iis_shortnames, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| dirbust-light     | web        | Basic web directory brute-force (surface-level directories only)                                                                         | 4           | ffuf, ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| dirbust-light     |            | Basic web directory brute-force (surface-level directories only)                                                                         | 4           | ffuf, ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| dotnet-audit      | web        | Comprehensive scan for all IIS/.NET specific modules and module settings                                                                 | 8           | ajaxpro, badsecrets, dotnetnuke, ffuf, ffuf_shortnames, httpx, iis_shortnames, telerik                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| dotnet-audit      |            | Comprehensive scan for all IIS/.NET specific modules and module settings                                                                 | 8           | ajaxpro, badsecrets, dotnetnuke, ffuf, ffuf_shortnames, httpx, iis_shortnames, telerik                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| email-enum        |            | Enumerate email addresses from APIs, web crawling, etc.                                                                                  | 8           | dehashed, dnscaa, dnstlsrpt, emailformat, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| fast              |            | Scan only the provided targets as fast as possible - no extra discovery                                                                  | 0           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| iis-shortnames    | web        | Recursively enumerate IIS shortnames                                                                                                     | 3           | ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| iis-shortnames    |            | Recursively enumerate IIS shortnames                                                                                                     | 3           | ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| kitchen-sink      |            | Everything everywhere all at once                                                                                                        | 87          | anubisdb, apkpure, asn, azure_realm, azure_tenant, baddns, baddns_direct, baddns_zone, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, bufferoverrun, builtwith, c99, censys, certspotter, chaos, code_repository, crt, dehashed, digitorus, dnsbimi, dnsbrute, dnsbrute_mutations, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, docker_pull, dockerhub, emailformat, ffuf, ffuf_shortnames, filedownload, fullhunt, git, git_clone, gitdumper, github_codesearch, github_org, github_workflows, gitlab, google_playstore, gowitness, hackertarget, httpx, hunterio, iis_shortnames, internetdb, ipneighbor, jadx, leakix, myssl, ntlm, oauth, otx, paramminer_cookies, paramminer_getparams, paramminer_headers, passivetotal, pgp, postman, postman_download, rapiddns, robots, securitytrails, securitytxt, shodan_dns, sitedossier, skymem, social, sslcert, subdomaincenter, subdomainradar, trickest, trufflehog, urlscan, virustotal, wappalyzer, wayback, zoomeye |
| nuclei            | nuclei     | Run nuclei scans against all discovered targets                                                                                          | 3           | httpx, nuclei, portfilter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| nuclei            |            | Run nuclei scans against all discovered targets                                                                                          | 3           | httpx, nuclei, portfilter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| nuclei-budget     | nuclei     | Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests | 3           | httpx, nuclei, portfilter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| nuclei-budget     |            | Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests | 3           | httpx, nuclei, portfilter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| nuclei-intense    | nuclei     | Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.        | 6           | httpx, nuclei, portfilter, robots, urlscan, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| nuclei-intense    |            | Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.        | 6           | httpx, nuclei, portfilter, robots, urlscan, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| nuclei-technology | nuclei     | Run nuclei scans against all discovered targets, running templates which match discovered technologies                                   | 3           | httpx, nuclei, portfilter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| nuclei-technology |            | Run nuclei scans against all discovered targets, running templates which match discovered technologies                                   | 3           | httpx, nuclei, portfilter                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| paramminer        | web        | Discover new web parameters via brute-force                                                                                              | 4           | httpx, paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| paramminer        |            | Discover new web parameters via brute-force                                                                                              | 4           | httpx, paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| spider            |            | Recursive web spider                                                                                                                     | 1           | httpx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| spider-intense    |            | Recursive web spider with more aggressive settings                                                                                       | 1           | httpx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| subdomain-enum    |            | Enumerate subdomains via APIs, brute-force                                                                                               | 52          | anubisdb, asn, azure_realm, azure_tenant, baddns_direct, baddns_zone, bevigil, binaryedge, bufferoverrun, builtwith, c99, censys, certspotter, chaos, crt, digitorus, dnsbimi, dnsbrute, dnsbrute_mutations, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, myssl, oauth, otx, passivetotal, postman, postman_download, rapiddns, securitytrails, securitytxt, shodan_dns, sitedossier, social, sslcert, subdomaincenter, subdomainradar, trickest, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| tech-detect       |            | Detect technologies via Wappalyzer, Nuclei, and FingerprintX                                                                             | 4           | fingerprintx, httpx, nuclei, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| web-basic         |            | Quick web scan                                                                                                                           | 18          | azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, ffuf_shortnames, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, securitytxt, sslcert, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| web-screenshots   |            | Take screenshots of webpages                                                                                                             | 3           | gowitness, httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| web-thorough      |            | Aggressive web scan                                                                                                                      | 29          | ajaxpro, azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dotnetnuke, ffuf_shortnames, filedownload, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, ntlm, oauth, robots, securitytxt, smuggler, sslcert, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
<!-- END BBOT PRESETS -->
