Below is a list of every default BBOT preset, including its YAML.

<!-- BBOT PRESET YAML -->
## **baddns**

Check for subdomain takeovers and other DNS issues.

??? note "`baddns.yml`"
    ```yaml title="~/.bbot/presets/baddns.yml"
    description: Check for subdomain takeovers and other DNS issues.
    
    modules:
      - baddns
    
    config:
      modules:
        baddns:
          enabled_submodules: [CNAME, MX, TXT]
          min_severity: LOW
          min_confidence: MEDIUM
    ```



Modules: [0]("")

## **baddns-heavy**

Run all baddns modules and submodules.

??? note "`baddns-heavy.yml`"
    ```yaml title="~/.bbot/presets/baddns-heavy.yml"
    description: Run all baddns modules and submodules.
    
    include:
      - baddns
    
    modules:
      - baddns_zone
      - baddns_direct
    
    config:
      modules:
        baddns:
          enabled_submodules: [CNAME, NS, MX, TXT, references, DMARC, SPF, MTA-STS, WILDCARD]
          min_severity: INFO
          min_confidence: UNKNOWN
        baddns_zone:
          min_severity: INFO
          min_confidence: UNKNOWN
        baddns_direct:
          min_severity: INFO
          min_confidence: UNKNOWN
    ```



Modules: [0]("")

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



Modules: [0]("")

## **code-enum**

Enumerate Git repositories, Docker images, etc.

??? note "`code-enum.yml`"
    ```yaml title="~/.bbot/presets/code-enum.yml"
    description: Enumerate Git repositories, Docker images, etc.
    
    flags:
      - code-enum
    ```



Modules: [0]("")

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
      - webbrute
      - wayback
    
    config:
      modules:
        iis_shortnames:
          # we exploit the shortnames vulnerability to produce URL_HINTs which are consumed by webbrute_shortnames
          detect_only: False
        webbrute:
          avoid_wafs: False
          max_depth: 3
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

Modules: [0]("")

## **dirbust-light**

Basic web directory brute-force (surface-level directories only)

??? note "`dirbust-light.yml`"
    ```yaml title="~/.bbot/presets/web/dirbust-light.yml"
    description: Basic web directory brute-force (surface-level directories only)
    
    include:
      - iis-shortnames
    
    modules:
      - webbrute
    
    config:
      modules:
        webbrute:
          # wordlist size = 1000
          lines: 1000
    ```

Category: web

Modules: [0]("")

## **dotnet-audit**

Comprehensive scan for all IIS/.NET specific modules and module settings

??? note "`dotnet-audit.yml`"
    ```yaml title="~/.bbot/presets/web/dotnet-audit.yml"
    description: Comprehensive scan for all IIS/.NET specific modules and module settings
    
    
    include:
      - iis-shortnames
    
    modules:
      - http
      - badsecrets
      - webbrute_shortnames
      - webbrute
      - telerik
      - ajaxpro
      - dotnetnuke
      - aspnet_bin_exposure
    
    config:
      modules:
        webbrute:
          extensions: asp,aspx,ashx,asmx,ascx
          ignore_case: True
        webbrute_shortnames:
          find_subwords: True
        telerik:
          exploit_RAU_crypto: True
          include_subdirs: True # Run against every directory, not the default first received URL per-host
    ```

Category: web

Modules: [0]("")

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



Modules: [0]("")

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

Modules: [0]("")

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
      - web
      - paramminer
      - dirbust-light
      - web-screenshots
      - baddns-heavy
    
    config:
      modules:
        baddns:
          enable_references: True
        dnsbrute:
          recursive_mutations: true
        dnscommonsrv:
          recursive_mutations: true
        webbrute:
          avoid_wafs: False
        wayback:
          urls: True
          parameters: True
          archive: True
    ```



Modules: [0]("")

## **lightfuzz**

Default fuzzing: all 9 submodules (cmdi, crypto, path, serial, sqli, ssti, xss, esi, ssrf) plus companion modules (badsecrets, hunt, reflected_parameters). POST fuzzing disabled but try_post_as_get enabled, so POST params are retested as GET. Skips confirmed WAFs.

??? note "`lightfuzz.yml`"
    ```yaml title="~/.bbot/presets/web/lightfuzz.yml"
    description: "Default fuzzing: all 9 submodules (cmdi, crypto, path, serial, sqli, ssti, xss, esi, ssrf) plus companion modules (badsecrets, hunt, reflected_parameters). POST fuzzing disabled but try_post_as_get enabled, so POST params are retested as GET. Skips confirmed WAFs."
    
    include:
      - lightfuzz-light
    
    modules:
      - badsecrets
      - hunt
      - reflected_parameters
      
    config:
      modules:
        lightfuzz:
          enabled_submodules: [cmdi,crypto,path,serial,sqli,ssti,xss,esi,ssrf]
          try_post_as_get: True
    ```

Category: web

Modules: [0]("")

## **lightfuzz-heavy**

Aggressive fuzzing: everything in lightfuzz, plus paramminer brute-force parameter discovery (headers, GET params, cookies), POST request fuzzing enabled, try_get_as_post enabled (GET params retested as POST), and robots.txt parsing. Still skips confirmed WAFs.

??? note "`lightfuzz-heavy.yml`"
    ```yaml title="~/.bbot/presets/web/lightfuzz-heavy.yml"
    description: "Aggressive fuzzing: everything in lightfuzz, plus paramminer brute-force parameter discovery (headers, GET params, cookies), POST request fuzzing enabled, try_get_as_post enabled (GET params retested as POST), and robots.txt parsing. Still skips confirmed WAFs."
    
    include:
      - lightfuzz
    
    flags:
      - web-paramminer
    
    modules:
      - robots
      - wayback
    
    config:
      modules:
        lightfuzz:
          enabled_submodules: [cmdi,crypto,path,serial,sqli,ssti,xss,esi,ssrf]
          disable_post: False
          try_post_as_get: True
          try_get_as_post: True
        wayback:
          urls: True
          parameters: True
    ```

Category: web

Modules: [0]("")

## **lightfuzz-light**

Minimal fuzzing: only path traversal, SQLi, and XSS submodules. No POST requests. No companion modules. Safest option for running alongside larger scans with minimal overhead.

??? note "`lightfuzz-light.yml`"
    ```yaml title="~/.bbot/presets/web/lightfuzz-light.yml"
    description: "Minimal fuzzing: only path traversal, SQLi, and XSS submodules. No POST requests. No companion modules. Safest option for running alongside larger scans with minimal overhead."
    
    modules:
      - http
      - lightfuzz
      - portfilter
      
    config:
      url_querystring_remove: False # don't strip off the querystring (BBOT normally does this; but lightfuzz needs it)
      url_querystring_collapse: True # in cases where the same parameter has multiple values, collapse them into a single parameter to save on fuzzing attempts
      modules:
        lightfuzz:
          enabled_submodules: [path,sqli,xss] # only look for the most common vulnerabilities
          disable_post: True # don't send POST requests (less aggressive)
          avoid_wafs: True
    
    conditions:
    - |
      {% if config.web.spider_distance == 0 %}
        {{ warn("Lightfuzz works much better with spider enabled! Consider adding 'spider' or 'spider-heavy' preset.") }}
      {% endif %}
    ```

Category: web

Modules: [0]("")

## **lightfuzz-max**

Maximum fuzzing: everything in lightfuzz-heavy, plus the heavy paramminer variant (1-3 letter brute-force on GET params, case mutation on case-sensitive backends, recycle_words on all paramminer modules), WAF targets are no longer skipped, each unique parameter-value pair is fuzzed individually (no collapsing), common headers like X-Forwarded-For are fuzzed even if not observed, and potential parameters are speculated from JSON/XML response bodies. Significantly increases scan time.

??? note "`lightfuzz-max.yml`"
    ```yaml title="~/.bbot/presets/web/lightfuzz-max.yml"
    description: "Maximum fuzzing: everything in lightfuzz-heavy, plus the heavy paramminer variant (1-3 letter brute-force on GET params, case mutation on case-sensitive backends, recycle_words on all paramminer modules), WAF targets are no longer skipped, each unique parameter-value pair is fuzzed individually (no collapsing), common headers like X-Forwarded-For are fuzzed even if not observed, and potential parameters are speculated from JSON/XML response bodies. Significantly increases scan time."
    
    include:
      - lightfuzz-heavy
      - paramminer-heavy
    
    config:
      url_querystring_collapse: False # in cases where the same parameter is observed multiple times, fuzz them individually instead of collapsing them into a single parameter
      modules:
        lightfuzz:
          force_common_headers: True # Fuzz common headers like X-Forwarded-For even if they're not observed on the target
          enabled_submodules: [cmdi,crypto,path,serial,sqli,ssti,xss,esi,ssrf]
          avoid_wafs: False
        excavate:
          speculate_params: True # speculate potential parameters extracted from JSON/XML web responses
        wayback:
          urls: True
          parameters: True
          archive: True
    ```

Category: web

Modules: [0]("")

## **lightfuzz-xss**

XSS-only: enables only the xss submodule with paramminer_getparams and reflected_parameters. POST disabled, no query string collapsing. Example of a focused single-submodule preset.

??? note "`lightfuzz-xss.yml`"
    ```yaml title="~/.bbot/presets/web/lightfuzz-xss.yml"
    description: "XSS-only: enables only the xss submodule with paramminer_getparams and reflected_parameters. POST disabled, no query string collapsing. Example of a focused single-submodule preset."
    
    modules:
      - http
      - lightfuzz
      - paramminer_getparams
      - reflected_parameters
      - portfilter
      
    config:
      url_querystring_remove: False
      url_querystring_collapse: False
      modules:
        lightfuzz:
          enabled_submodules: [xss]
          disable_post: True
    
    conditions:
      - |
        {% if config.web.spider_distance == 0 %}
          {{ warn("The lightfuzz-xss preset works much better with spider enabled! Consider adding 'spider' or 'spider-heavy' preset.") }}
        {% endif %}
    ```

Category: web

Modules: [0]("")

## **nuclei**

Run nuclei scans against all discovered targets

??? note "`nuclei.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei.yml"
    description: Run nuclei scans against all discovered targets
    
    modules:
      - http
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

Modules: [0]("")

## **nuclei-budget**

Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests

??? note "`nuclei-budget.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei-budget.yml"
    description: Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests
    
    modules:
      - http
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

Modules: [0]("")

## **nuclei-heavy**

Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.

??? note "`nuclei-heavy.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei-heavy.yml"
    description: Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.
    
    modules:
      - http
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
          {{ warn("The 'nuclei-heavy' preset turns the 'directory_only' limitation off on the nuclei module. To make the best use of this, you may want to enable spidering with 'spider' or 'spider-heavy' preset.") }}
        {% endif %}
    
    
    # Example for also running a dirbust
    
    #include:
    #  - dirbust-light
    ```

Category: nuclei

Modules: [0]("")

## **nuclei-technology**

Run nuclei scans against all discovered targets, running templates which match discovered technologies

??? note "`nuclei-technology.yml`"
    ```yaml title="~/.bbot/presets/nuclei/nuclei-technology.yml"
    description: Run nuclei scans against all discovered targets, running templates which match discovered technologies
    
    modules:
      - http
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

Modules: [0]("")

## **paramminer**

Discover new web parameters via brute-force, and analyze them with additional modules

??? note "`paramminer.yml`"
    ```yaml title="~/.bbot/presets/web/paramminer.yml"
    description: Discover new web parameters via brute-force, and analyze them with additional modules
    
    flags:
      - web-paramminer
    
    modules:
      - http
      - reflected_parameters
      - hunt
    
    conditions:
      - |
        {% if config.web.spider_distance == 0 %}
          {{ warn("The paramminer preset works much better with spider enabled! Consider adding 'spider' or 'spider-heavy' preset.") }}
        {% endif %}
    ```

Category: web

Modules: [0]("")

## **paramminer-heavy**

Aggressive paramminer brute-force: enables 1-3 letter combination brute-force on GET parameters and case mutation (camelCase / Title-case variants) on case-sensitive backends. Significantly increases scan time.

??? note "`paramminer-heavy.yml`"
    ```yaml title="~/.bbot/presets/web/paramminer-heavy.yml"
    description: "Aggressive paramminer brute-force: enables 1-3 letter combination brute-force on GET parameters and case mutation (camelCase / Title-case variants) on case-sensitive backends. Significantly increases scan time."
    
    include:
      - paramminer
    
    config:
      modules:
        paramminer_getparams:
          brute_short: True
          mutate_case: True
          recycle_words: True
        paramminer_headers:
          recycle_words: True
        paramminer_cookies:
          recycle_words: True
    ```

Category: web

Modules: [0]("")

## **spider**

Recursive web spider

??? note "`spider.yml`"
    ```yaml title="~/.bbot/presets/spider.yml"
    description: Recursive web spider
    
    modules:
      - http
    
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



Modules: [0]("")

## **spider-heavy**

Recursive web spider with more aggressive settings

??? note "`spider-heavy.yml`"
    ```yaml title="~/.bbot/presets/spider-heavy.yml"
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



Modules: [0]("")

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



Modules: [0]("")

## **tech-detect**

Detect technologies via Nuclei, and FingerprintX

??? note "`tech-detect.yml`"
    ```yaml title="~/.bbot/presets/tech-detect.yml"
    description: Detect technologies via Nuclei, and FingerprintX
    
    modules:
      - nuclei
      - fingerprintx
    
    config:
      modules:
        nuclei:
          tags: tech
    ```



Modules: [0]("")

## **virtualhost**

Virtual host discovery: subdomain brute-force and mutations against the target host's Host header / SNI.

??? note "`virtualhost.yml`"
    ```yaml title="~/.bbot/presets/web/virtualhost.yml"
    description: "Virtual host discovery: subdomain brute-force and mutations against the target host's Host header / SNI."
    
    modules:
      - virtualhost
    ```

Category: web

Modules: [0]("")

## **virtualhost-heavy**

Aggressive virtual host discovery: everything in virtualhost, plus special-host probing, certificate SAN extraction, and wordcloud-driven candidate testing.

??? note "`virtualhost-heavy.yml`"
    ```yaml title="~/.bbot/presets/web/virtualhost-heavy.yml"
    description: "Aggressive virtual host discovery: everything in virtualhost, plus special-host probing, certificate SAN extraction, and wordcloud-driven candidate testing."
    
    include:
      - virtualhost
    
    config:
      modules:
        virtualhost:
          special_hosts: True
          certificate_sans: True
          wordcloud_check: True
    ```

Category: web

Modules: [0]("")

## **waf-bypass**

WAF bypass detection with subdomain enumeration

??? note "`waf-bypass.yml`"
    ```yaml title="~/.bbot/presets/waf-bypass.yml"
    description: WAF bypass detection with subdomain enumeration
    
    flags:
      # enable subdomain enumeration to find potential bypass targets
      - subdomain-enum
    
    modules:
      # explicitly enable the waf_bypass module for detection
      - waf_bypass
      # ensure http is enabled for web probing
      - http
    
    config:
      # waf_bypass module configuration
      modules:
        waf_bypass:
          similarity_threshold: 0.90
          search_ip_neighbors: true
          neighbor_cidr: 24 
    ```



Modules: [0]("")

## **wayback**

Discover URLs and interesting archived files via the Wayback Machine

??? note "`wayback.yml`"
    ```yaml title="~/.bbot/presets/wayback.yml"
    description: Discover URLs and interesting archived files via the Wayback Machine
    
    include:
      - subdomain-enum
    
    modules:
      - wayback
    
    config:
      modules:
        wayback:
          urls: True
    ```



Modules: [0]("")

## **wayback-heavy**

Full Wayback Machine integration - URL discovery, parameter extraction, archived page retrieval, and interesting file detection

??? note "`wayback-heavy.yml`"
    ```yaml title="~/.bbot/presets/wayback-heavy.yml"
    description: Full Wayback Machine integration - URL discovery, parameter extraction, archived page retrieval, and interesting file detection
    
    include:
      - subdomain-enum
    
    modules:
      - wayback
      - badsecrets
    
    config:
      modules:
        wayback:
          urls: True
          parameters: True
          archive: True
    ```



Modules: [0]("")

## **web**

Quick web scan

??? note "`web.yml`"
    ```yaml title="~/.bbot/presets/web.yml"
    description: Quick web scan
    
    include:
      - iis-shortnames
    
    flags:
      - web
    ```



Modules: [0]("")

## **web-heavy**

Aggressive web scan

??? note "`web-heavy.yml`"
    ```yaml title="~/.bbot/presets/web-heavy.yml"
    description: Aggressive web scan
    
    include:
      # include the web preset
      - web
    
    flags:
      - web-heavy
    ```



Modules: [0]("")

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



Modules: [0]("")
<!-- END BBOT PRESET YAML -->

## Table of Default Presets

Here is a the same data, but in a table:

<!-- BBOT PRESETS -->
| Preset            | Category   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | # Modules   | Modules                                                                                            |
|-------------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|----------------------------------------------------------------------------------------------------|
| baddns            |            | Check for subdomain takeovers and other DNS issues.                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 1           | baddns                                                                                             |
| baddns-heavy      |            | Run all baddns modules and submodules.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | 3           | baddns, baddns_direct, baddns_zone                                                                 |
| cloud-enum        |            | Enumerate cloud resources such as storage buckets, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 0           |                                                                                                    |
| code-enum         |            | Enumerate Git repositories, Docker images, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 0           |                                                                                                    |
| dirbust-heavy     | web        | Recursive web directory brute-force (aggressive)                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 3           | http, wayback, webbrute                                                                            |
| dirbust-light     | web        | Basic web directory brute-force (surface-level directories only)                                                                                                                                                                                                                                                                                                                                                                                                                                        | 1           | webbrute                                                                                           |
| dotnet-audit      | web        | Comprehensive scan for all IIS/.NET specific modules and module settings                                                                                                                                                                                                                                                                                                                                                                                                                                | 8           | ajaxpro, aspnet_bin_exposure, badsecrets, dotnetnuke, http, telerik, webbrute, webbrute_shortnames |
| email-enum        |            | Enumerate email addresses from APIs, web crawling, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 0           |                                                                                                    |
| fast              |            | Scan only the provided targets as fast as possible - no extra discovery                                                                                                                                                                                                                                                                                                                                                                                                                                 | 0           |                                                                                                    |
| iis-shortnames    | web        | Recursively enumerate IIS shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | 0           |                                                                                                    |
| kitchen-sink      |            | Everything everywhere all at once                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 7           | baddns, baddns_direct, baddns_zone, http, hunt, reflected_parameters, webbrute                     |
| lightfuzz         | web        | Default fuzzing: all 9 submodules (cmdi, crypto, path, serial, sqli, ssti, xss, esi, ssrf) plus companion modules (badsecrets, hunt, reflected_parameters). POST fuzzing disabled but try_post_as_get enabled, so POST params are retested as GET. Skips confirmed WAFs.                                                                                                                                                                                                                                | 6           | badsecrets, http, hunt, lightfuzz, portfilter, reflected_parameters                                |
| lightfuzz-heavy   | web        | Aggressive fuzzing: everything in lightfuzz, plus paramminer brute-force parameter discovery (headers, GET params, cookies), POST request fuzzing enabled, try_get_as_post enabled (GET params retested as POST), and robots.txt parsing. Still skips confirmed WAFs.                                                                                                                                                                                                                                   | 8           | badsecrets, http, hunt, lightfuzz, portfilter, reflected_parameters, robots, wayback               |
| lightfuzz-light   | web        | Minimal fuzzing: only path traversal, SQLi, and XSS submodules. No POST requests. No companion modules. Safest option for running alongside larger scans with minimal overhead.                                                                                                                                                                                                                                                                                                                         | 3           | http, lightfuzz, portfilter                                                                        |
| lightfuzz-max     | web        | Maximum fuzzing: everything in lightfuzz-heavy, plus the heavy paramminer variant (1-3 letter brute-force on GET params, case mutation on case-sensitive backends, recycle_words on all paramminer modules), WAF targets are no longer skipped, each unique parameter-value pair is fuzzed individually (no collapsing), common headers like X-Forwarded-For are fuzzed even if not observed, and potential parameters are speculated from JSON/XML response bodies. Significantly increases scan time. | 8           | badsecrets, http, hunt, lightfuzz, portfilter, reflected_parameters, robots, wayback               |
| lightfuzz-xss     | web        | XSS-only: enables only the xss submodule with paramminer_getparams and reflected_parameters. POST disabled, no query string collapsing. Example of a focused single-submodule preset.                                                                                                                                                                                                                                                                                                                   | 5           | http, lightfuzz, paramminer_getparams, portfilter, reflected_parameters                            |
| nuclei            | nuclei     | Run nuclei scans against all discovered targets                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 3           | http, nuclei, portfilter                                                                           |
| nuclei-budget     | nuclei     | Run nuclei scans against all discovered targets, using budget mode to look for low hanging fruit with greatly reduced number of requests                                                                                                                                                                                                                                                                                                                                                                | 3           | http, nuclei, portfilter                                                                           |
| nuclei-heavy      | nuclei     | Run nuclei scans against all discovered targets, allowing for spidering, against ALL URLs, and with additional discovery modules.                                                                                                                                                                                                                                                                                                                                                                       | 6           | http, nuclei, portfilter, robots, urlscan, wayback                                                 |
| nuclei-technology | nuclei     | Run nuclei scans against all discovered targets, running templates which match discovered technologies                                                                                                                                                                                                                                                                                                                                                                                                  | 3           | http, nuclei, portfilter                                                                           |
| paramminer        | web        | Discover new web parameters via brute-force, and analyze them with additional modules                                                                                                                                                                                                                                                                                                                                                                                                                   | 3           | http, hunt, reflected_parameters                                                                   |
| paramminer-heavy  | web        | Aggressive paramminer brute-force: enables 1-3 letter combination brute-force on GET parameters and case mutation (camelCase / Title-case variants) on case-sensitive backends. Significantly increases scan time.                                                                                                                                                                                                                                                                                      | 3           | http, hunt, reflected_parameters                                                                   |
| spider            |            | Recursive web spider                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | 1           | http                                                                                               |
| spider-heavy      |            | Recursive web spider with more aggressive settings                                                                                                                                                                                                                                                                                                                                                                                                                                                      | 1           | http                                                                                               |
| subdomain-enum    |            | Enumerate subdomains via APIs, brute-force                                                                                                                                                                                                                                                                                                                                                                                                                                                              | 0           |                                                                                                    |
| tech-detect       |            | Detect technologies via Nuclei, and FingerprintX                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 2           | fingerprintx, nuclei                                                                               |
| virtualhost       | web        | Virtual host discovery: subdomain brute-force and mutations against the target host's Host header / SNI.                                                                                                                                                                                                                                                                                                                                                                                                | 1           | virtualhost                                                                                        |
| virtualhost-heavy | web        | Aggressive virtual host discovery: everything in virtualhost, plus special-host probing, certificate SAN extraction, and wordcloud-driven candidate testing.                                                                                                                                                                                                                                                                                                                                            | 1           | virtualhost                                                                                        |
| waf-bypass        |            | WAF bypass detection with subdomain enumeration                                                                                                                                                                                                                                                                                                                                                                                                                                                         | 2           | http, waf_bypass                                                                                   |
| wayback           |            | Discover URLs and interesting archived files via the Wayback Machine                                                                                                                                                                                                                                                                                                                                                                                                                                    | 1           | wayback                                                                                            |
| wayback-heavy     |            | Full Wayback Machine integration - URL discovery, parameter extraction, archived page retrieval, and interesting file detection                                                                                                                                                                                                                                                                                                                                                                         | 2           | badsecrets, wayback                                                                                |
| web               |            | Quick web scan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | 0           |                                                                                                    |
| web-heavy         |            | Aggressive web scan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 0           |                                                                                                    |
| web-screenshots   |            | Take screenshots of webpages                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | 0           |                                                                                                    |
<!-- END BBOT PRESETS -->
