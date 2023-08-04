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
