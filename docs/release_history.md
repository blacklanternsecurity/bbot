## v1.1.2
October 24, 2023

### Improvements
- https://github.com/blacklanternsecurity/bbot/pull/776
- https://github.com/blacklanternsecurity/bbot/pull/772
- https://github.com/blacklanternsecurity/bbot/pull/783
- https://github.com/blacklanternsecurity/bbot/pull/790
- https://github.com/blacklanternsecurity/bbot/pull/797
- https://github.com/blacklanternsecurity/bbot/pull/798
- https://github.com/blacklanternsecurity/bbot/pull/799

### Bugfixes
- https://github.com/blacklanternsecurity/bbot/pull/780
- https://github.com/blacklanternsecurity/bbot/pull/787
- https://github.com/blacklanternsecurity/bbot/pull/788
- https://github.com/blacklanternsecurity/bbot/pull/791

### New Modules
- https://github.com/blacklanternsecurity/bbot/pull/774

## v1.1.1
October 11, 2023

Includes webhook output modules - Discord, Slack, and Teams!

![image](https://github.com/blacklanternsecurity/bbot/assets/20261699/72e3e940-a41a-4c7a-952e-49a1d7cae526)

### Improvements
- https://github.com/blacklanternsecurity/bbot/pull/677
- https://github.com/blacklanternsecurity/bbot/pull/674
- https://github.com/blacklanternsecurity/bbot/pull/683
- https://github.com/blacklanternsecurity/bbot/pull/740
- https://github.com/blacklanternsecurity/bbot/pull/743
- https://github.com/blacklanternsecurity/bbot/pull/748
- https://github.com/blacklanternsecurity/bbot/pull/749
- https://github.com/blacklanternsecurity/bbot/pull/751
- https://github.com/blacklanternsecurity/bbot/pull/692

### Bugfixes
- https://github.com/blacklanternsecurity/bbot/pull/691
- https://github.com/blacklanternsecurity/bbot/pull/684
- https://github.com/blacklanternsecurity/bbot/pull/669
- https://github.com/blacklanternsecurity/bbot/pull/664
- https://github.com/blacklanternsecurity/bbot/pull/737
- https://github.com/blacklanternsecurity/bbot/pull/741
- https://github.com/blacklanternsecurity/bbot/pull/744
- https://github.com/blacklanternsecurity/bbot/issues/760
- https://github.com/blacklanternsecurity/bbot/issues/759
- https://github.com/blacklanternsecurity/bbot/issues/758
- https://github.com/blacklanternsecurity/bbot/pull/764
- https://github.com/blacklanternsecurity/bbot/pull/773

### New Modules
- https://github.com/blacklanternsecurity/bbot/pull/689
- https://github.com/blacklanternsecurity/bbot/pull/665
- https://github.com/blacklanternsecurity/bbot/pull/663

## v1.1.0
August 4, 2023

**New Features**:

- Complete Asyncification
- Documentation + auto-updating pipelines
- Ability to list flags and their descriptions with `-lf`
- Fine-grained rate-limiting for HTTP and DNS

**Improvements / Fixes**:

- Better tests (one for each individual module, 91% test coverage)
- New and improved paramminer modules
- Misc bugfixes

**New Modules**:

- Git (detects exposed .git folder on websites)
- [Subdomain Center](https://www.subdomain.center/) (subdomain enumeration)
- [Columbus API](https://columbus.elmasy.com/) (subdomain enumeration)
- MySSL (subdomain enumeration)
- Sitedossier (subdomain enumeration)
- Digitorus (subdomain enumeration)
- Nmap (port scanner, more reliable than naabu)
    - Naabu has been removed due to reliability issues
- NSEC (DNSSEC zone-walking for subdomain enumeration)
- OAUTH (Enumerates OAUTH / OpenID-Connect, detects sprayable endpoints)
- Azure Realm (Detects Managed/Federated Azure Tenants)
- Subdomains output module


## v1.0.5
March 10, 2023

**New Modules**:

- [Badsecrets](https://github.com/blacklanternsecurity/badsecrets) ([blacklist3r](https://github.com/NotSoSecure/Blacklist3r) but better!)
- Subdomain Hijacking (uses [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz))
- [WafW00f](https://github.com/EnableSecurity/wafw00f)
- [Fingerprintx](https://github.com/praetorian-inc/fingerprintx)
- [Masscan](https://github.com/robertdavidgraham/masscan)
- Robots.txt
- Web Report
- IIS shortnames (Pure Python rewrite)

**New Features**:

- Automatic tagging of cloud resources (with [cloudcheck](https://github.com/blacklanternsecurity/cloudcheck))
- Significant performance increases
- Bug fixes
- Better tests + code coverage
- Support for punycode (non-ascii) domains
- Better support for non-64-bit systems
- Enter key now toggles verbosity during scan


## v1.0.4
December 15, 2022

**New Modules**:

- Storage buckets:
    - Azure
    - GCP
    - AWS
    - DigitalOcean
- ipstack (geolocation)
- BeVigil
- ASN (rewrite)

**New Features**:

- Colored vulnerabilities on CLI
- Log full nuclei output
- Various bugfixes
- Better handling of:
    - DNS wildcards
    - Infinite DNS-record chains
    - Infinite HTTP redirects
- Improved module tests

## v1.0.3
October 12, 2022

**Changes**:

- Tag URL events with their corresponding IP address
- Automatic docker hub publishing
- Added `retries` option for httpx module
- Added `asset_inventory` output module
- Improvements to nuclei module
- Avoid unnecessary failed sudo attempts during dependency install
- Improved Python API
- Added AnubisDB module
- Various bugfixes
- Add examples to `--help` output
- Reduce annoying warnings on free API modules
- Update iis_shortnames .jar dependency
- Updated documentation to explain targets, whitelists, blacklists
- Added help for module-specific options
- Added warning if unable to validate public DNS servers (for massdns)
- Various performance optimizations
- Various bugfixes
- Fix Pypi auto-publishing
- Added bug report template
- Added examples in README
- Improved wildcard detection
- Added DNS retry functionality
- Improved excavate hostname extraction
- Added command-line option for installing all dependencies
- Improved gowitness dependency install, improved tests
