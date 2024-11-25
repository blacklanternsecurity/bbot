# Scanning Overview

## Scan Names

Every BBOT scan gets a random, mildly-entertaining name like **`demonic_jimmy`**. Output for that scan, including scan stats and any web screenshots, are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed.

If you don't want a random name, you can change it with `-n`. You can also change the location of BBOT's output with `-o`:

```bash
# save everything to the folder "my_scan" in the current directory
bbot -t evilcorp.com -f subdomain-enum -m gowitness -n my_scan -o .
```

If you reuse a scan name, BBOT will automatically append to your previous output files.

## Targets (`-t`)

Targets declare what's in-scope, and seed a scan with initial data. BBOT accepts an unlimited number of targets. They can be any of the following:

- `DNS_NAME` (`evilcorp.com`)
- `IP_ADDRESS` (`1.2.3.4`)
- `IP_RANGE` (`1.2.3.0/24`)
- `OPEN_TCP_PORT` (`192.168.0.1:80`)
- `URL` (`https://www.evilcorp.com`)

Note that BBOT only discriminates down to the host level. This means, for example, if you specify a URL `https://www.evilcorp.com` as the target, the scan will be *seeded* with that URL, but the scope of the scan will be the entire host, `www.evilcorp.com`. Other ports/URLs on that same host may also be scanned.

You can specify targets directly on the command line, load them from files, or both! For example:

```bash
$ cat targets.txt
4.3.2.1
10.0.0.2:80
1.2.3.0/24
evilcorp.com
evilcorp.co.uk
https://www.evilcorp.co.uk

# load targets from a file and from the command-line
$ bbot -t targets.txt fsociety.com 5.6.7.0/24 -m nmap
```

On start, BBOT automatically converts Targets into [Events](events.md).

## Modules (`-m`)

To see a full list of modules and their descriptions, use `bbot -l` or see [List of Modules](../modules/list_of_modules.md).

Modules are the part of BBOT that does the work -- port scanning, subdomain brute-forcing, API querying, etc. Modules consume [Events](events.md) (`IP_ADDRESS`, `DNS_NAME`, etc.) from each other, process the data in a useful way, then emit the results as new events. You can enable individual modules with `-m`.

```bash
# Enable modules: nmap, sslcert, and httpx
bbot -t www.evilcorp.com -m nmap sslcert httpx
```

### Types of Modules

Modules fall into three categories:

- **Scan Modules**:
    - These make up the majority of modules. Examples are `nmap`, `sslcert`, `httpx`, etc. Enable with `-m`.
- **Output Modules**:
    - These output scan data to different formats/destinations. `human`, `json`, and `csv` are enabled by default. Enable others with `-om`. (See: [Output](output.md))
- **Internal Modules**:
    - These modules perform essential, common-sense tasks. They are always enabled, unless explicitly disabled via the config (e.g. `-c speculate=false`).
        - `aggregate`: Summarizes results at the end of a scan
        - `excavate`: Extracts useful data such as subdomains from webpages, etc.
        - `speculate`: Intelligently infers new events, e.g. `OPEN_TCP_PORT` from `URL` or `IP_ADDRESS` from `IP_NETWORK`.

For details in the inner workings of modules, see [Creating a Module](../contribution.md#creating-a-module).

## Flags (`-f`)

Flags are how BBOT categorizes its modules. In a way, you can think of them as groups. Flags let you enable a bunch of similar modules at the same time without having to specify them each individually. For example, `-f subdomain-enum` would enable every module with the `subdomain-enum` flag.

```bash
# list all subdomain-enum modules
bbot -f subdomain-enum -l
```

### Filtering Modules

Modules can be easily enabled/disabled based on their flags:

- `-f` Enable these flags (e.g. `-f subdomain-enum`)
- `-rf` Require modules to have this flag (e.g. `-rf safe`)
- `-ef` Exclude these flags (e.g. `-ef slow`)
- `-em` Exclude these individual modules (e.g. `-em ipneighbor`)
- `-lf` List all available flags

Every module is either `safe` or `aggressive`, and either `active` or `passive`. These can be useful for filtering. For example, if you wanted to enable all the `safe` modules, but exclude active ones, you could do:

```bash
# Enable safe modules but exclude active ones
bbot -t evilcorp.com -f safe -ef active
```

This is equivalent to requiring the passive flag:

```bash
# Enable safe modules but only if they're also passive
bbot -t evilcorp.com -f safe -rf passive
```

A single module can have multiple flags. For example, the `securitytrails` module is `passive`, `safe`, `subdomain-enum`. Below is a full list of flags and their associated modules.

### List of Flags

<!-- BBOT MODULE FLAGS -->
| Flag             | # Modules   | Description                                                    | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|------------------|-------------|----------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| safe             | 92          | Non-intrusive, safe to run                                     | affiliates, aggregate, ajaxpro, anubisdb, apkpure, asn, azure_realm, azure_tenant, baddns, baddns_direct, baddns_zone, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, bufferoverrun, builtwith, c99, censys, certspotter, chaos, code_repository, columbus, credshed, crt, dehashed, digitorus, dnsbimi, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, docker_pull, dockerhub, emailformat, extractous, filedownload, fingerprintx, fullhunt, git, git_clone, github_codesearch, github_org, github_workflows, gitlab, google_playstore, gowitness, hackertarget, httpx, hunt, hunterio, iis_shortnames, internetdb, ip2location, ipstack, jadx, leakix, myssl, newsletters, ntlm, oauth, otx, passivetotal, pgp, portscan, postman, postman_download, rapiddns, robots, secretsdb, securitytrails, securitytxt, shodan_dns, sitedossier, skymem, social, sslcert, subdomaincenter, subdomainradar, trickest, trufflehog, urlscan, viewdns, virustotal, wappalyzer, wayback, zoomeye |
| passive          | 67          | Never connects to target systems                               | affiliates, aggregate, anubisdb, apkpure, asn, azure_realm, azure_tenant, bevigil, binaryedge, bucket_file_enum, bufferoverrun, builtwith, c99, censys, certspotter, chaos, code_repository, columbus, credshed, crt, dehashed, digitorus, dnsbimi, dnscaa, dnsdumpster, dnstlsrpt, docker_pull, dockerhub, emailformat, excavate, extractous, fullhunt, git_clone, github_codesearch, github_org, github_workflows, google_playstore, hackertarget, hunterio, internetdb, ip2location, ipneighbor, ipstack, jadx, leakix, myssl, otx, passivetotal, pgp, postman, postman_download, rapiddns, securitytrails, shodan_dns, sitedossier, skymem, social, speculate, subdomaincenter, subdomainradar, trickest, trufflehog, urlscan, viewdns, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                   |
| subdomain-enum   | 53          | Enumerates subdomains                                          | anubisdb, asn, azure_realm, azure_tenant, baddns_direct, baddns_zone, bevigil, binaryedge, bufferoverrun, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnsbimi, dnsbrute, dnsbrute_mutations, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, myssl, oauth, otx, passivetotal, postman, postman_download, rapiddns, securitytrails, securitytxt, shodan_dns, sitedossier, sslcert, subdomaincenter, subdomainradar, subdomains, trickest, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| active           | 47          | Makes active connections to target systems                     | ajaxpro, baddns, baddns_direct, baddns_zone, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dnsbrute, dnsbrute_mutations, dnscommonsrv, dotnetnuke, ffuf, ffuf_shortnames, filedownload, fingerprintx, generic_ssrf, git, gitlab, gowitness, host_header, httpx, hunt, iis_shortnames, newsletters, ntlm, nuclei, oauth, paramminer_cookies, paramminer_getparams, paramminer_headers, portscan, robots, secretsdb, securitytxt, smuggler, sslcert, telerik, url_manipulation, vhost, wafw00f, wappalyzer, wpscan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| aggressive       | 20          | Generates a large amount of network traffic                    | bypass403, dastardly, dnsbrute, dnsbrute_mutations, dotnetnuke, ffuf, ffuf_shortnames, generic_ssrf, host_header, ipneighbor, nuclei, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, telerik, url_manipulation, vhost, wafw00f, wpscan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| web-basic        | 18          | Basic, non-intrusive web scan functionality                    | azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, secretsdb, securitytxt, sslcert, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| cloud-enum       | 16          | Enumerates cloud resources                                     | azure_realm, azure_tenant, baddns, baddns_direct, baddns_zone, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, dnsbimi, dnstlsrpt, httpx, oauth, securitytxt                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| code-enum        | 14          | Find public code repositories and search them for secrets etc. | apkpure, code_repository, docker_pull, dockerhub, git, git_clone, github_codesearch, github_org, github_workflows, gitlab, google_playstore, postman, postman_download, trufflehog                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| web-thorough     | 12          | More advanced web scanning functionality                       | ajaxpro, bucket_digitalocean, bypass403, dastardly, dotnetnuke, ffuf_shortnames, generic_ssrf, host_header, hunt, smuggler, telerik, url_manipulation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| slow             | 11          | May take a long time to complete                               | bucket_digitalocean, dastardly, dnsbrute_mutations, docker_pull, fingerprintx, git_clone, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| affiliates       | 9           | Discovers affiliated hostnames/domains                         | affiliates, azure_realm, azure_tenant, builtwith, oauth, sslcert, trickest, viewdns, zoomeye                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| email-enum       | 9           | Enumerates email addresses                                     | dehashed, dnscaa, dnstlsrpt, emailformat, emails, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| deadly           | 4           | Highly aggressive                                              | dastardly, ffuf, nuclei, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| baddns           | 3           | Runs all modules from the DNS auditing tool BadDNS             | baddns, baddns_direct, baddns_zone                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| web-paramminer   | 3           | Discovers HTTP parameters through brute-force                  | paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| iis-shortnames   | 2           | Scans for IIS Shortname vulnerability                          | ffuf_shortnames, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| portscan         | 2           | Discovers open ports                                           | internetdb, portscan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| report           | 2           | Generates a report at the end of the scan                      | affiliates, asn                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| social-enum      | 2           | Enumerates social media                                        | httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| service-enum     | 1           | Identifies protocols running on open ports                     | fingerprintx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| subdomain-hijack | 1           | Detects hijackable subdomains                                  | baddns                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| web-screenshots  | 1           | Takes screenshots of web pages                                 | gowitness                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
<!-- END BBOT MODULE FLAGS --> 

## Dependencies

BBOT modules have external dependencies ranging from OS packages (`openssl`) to binaries (`nmap`) to Python libraries (`wappalyzer`). When a module is enabled, installation of its dependencies happens at runtime with [Ansible](https://github.com/ansible/ansible). BBOT provides several command-line flags to control how dependencies are installed.

- `--no-deps` - Don't install module dependencies
- `--force-deps` - Force install all module dependencies
- `--retry-deps` - Try again to install failed module dependencies
- `--ignore-failed-deps` - Run modules even if they have failed dependencies
- `--install-all-deps` - Install dependencies for all modules (useful if you are provisioning a pentest system and want to install everything ahead of time)

For details on how Ansible playbooks are attached to BBOT modules, see [How to Write a Module](../contribution.md#module-dependencies).

## Scope

For pentesters and bug bounty hunters, staying in scope is extremely important. BBOT takes this seriously, meaning that active modules (e.g. `nuclei`) will only touch in-scope resources.

By default, scope is whatever you specify with `-t`. This includes child subdomains. For example, if you specify `-t evilcorp.com`, all its subdomains (`www.evilcorp.com`, `mail.evilcorp.com`, etc.) also become in-scope.

### Scope Distance

Since BBOT is recursive, it would quickly resort to scanning the entire internet without some kind of restraining mechanism. To solve this problem, every [event](events.md) discovered by BBOT is assigned a **Scope Distance**. Scope distance represents how far out from the main scope that data was discovered.

For example, if your target is `evilcorp.com`, `www.evilcorp.com` would have a scope distance of `0` (i.e. in-scope). If BBOT discovers that `www.evilcorp.com` resolves to `1.2.3.4`, `1.2.3.4` is one hop away, which means it would have a scope distance of `1`. If `1.2.3.4` has a PTR record that points to `ecorp.blob.core.windows.net`, `ecorp.blob.core.windows.net` is two hops away, so its scope distance is `2`.

Scope distance continues to increase the further out you get. Most modules (e.g. `nuclei` and `nmap`) only consume in-scope events. Certain other passive modules such as `asn` accept out to distance `1`. By default, DNS resolution happens out to a distance of `2`. Upon its discovery, any [event](events.md) that's determined to be in-scope (e.g. `www.evilcorp.com`) immediately becomes distance `0`, and the cycle starts over.

#### Displaying Out-of-scope Events

By default, BBOT only displays in-scope events (with a few exceptions such as `STORAGE_BUCKET`s). If you want to see more, you must increase the [config](configuration.md) value of `scope.report_distance`:

```bash
# display out-of-scope events up to one hop away from the main scope
bbot -t evilcorp.com -f subdomain-enum -c scope.report_distance=1
```

### Strict Scope

If you want to scan **_only_** that specific target hostname and none of its children, you can specify `--strict-scope`.

Note that `--strict-scope` only applies to targets and whitelists, but not blacklists. This means that if you put `internal.evilcorp.com` in your blacklist, you can be sure none of its subdomains will be scanned, even when using `--strict-scope`.

### Whitelists and Blacklists

BBOT allows precise control over scope with whitelists and blacklists. These both use the same syntax as `--target`, meaning they accept the same event types, and you can specify an unlimited number of them, via a file, the CLI, or both.

#### Whitelists

`--whitelist` enables you to override what's in scope. For example, if you want to run nuclei against `evilcorp.com`, but stay only inside their corporate IP range of `1.2.3.0/24`, you can accomplish this like so:

```bash
# Seed scan with evilcorp.com, but restrict scope to 1.2.3.0/24
bbot -t evilcorp.com --whitelist 1.2.3.0/24 -f subdomain-enum -m nmap nuclei --allow-deadly
```

#### Blacklists

`--blacklist` takes ultimate precedence. Anything in the blacklist is completely excluded from the scan, even if it's in the whitelist.

```bash
# Scan evilcorp.com, but exclude internal.evilcorp.com and its children
bbot -t evilcorp.com --blacklist internal.evilcorp.com -f subdomain-enum -m nmap nuclei --allow-deadly
```

#### Blacklist by Regex

Blacklists also accept regex patterns. These regexes are are checked against the full URL, including the host and path.

To specify a regex, prefix the pattern with `RE:`. For example, to exclude all events containing "signout", you could do:

```bash
bbot -t evilcorp.com --blacklist "RE:signout"
```

Note that this would blacklist both of the following events:

- `[URL]       http://evilcorp.com/signout.aspx`
- `[DNS_NAME]  signout.evilcorp.com`

If you only want to blacklist the URL, you could narrow the regex like so:

```bash
bbot -t evilcorp.com --blacklist 'RE:signout\.aspx$'
```

Similar to targets and whitelists, blacklists can be specified in your preset. The `spider` preset makes use of this to prevent the spider from following logout links:

```yaml title="spider.yml"
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

## DNS Wildcards

BBOT has robust wildcard detection built-in. It can reliably detect wildcard domains, and will tag them accordingly:

```text
[DNS_NAME]      github.io   TARGET  (a-record, a-wildcard-domain, aaaa-wildcard-domain, wildcard-domain)
                                               ^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^
```

Wildcard hosts are collapsed into a single host beginning with `_wildcard`:

```text
[DNS_NAME]      _wildcard.github.io     TARGET  (a-record, a-wildcard, a-wildcard-domain, aaaa-record, aaaa-wildcard, aaaa-wildcard-domain, wildcard, wildcard-domain)
                ^^^^^^^^^
```

If you don't want this, you can disable wildcard detection on a domain-to-domain basis in the [config](configuration.md):

```yaml title="~/.bbot/config/bbot.yml"
dns:
  wildcard_ignore:
    - evilcorp.com
    - evilcorp.co.uk
```

There are certain edge cases (such as with dynamic DNS rules) where BBOT's wildcard detection fails. In these cases, you can try increasing the number of wildcard checks in the config:

```yaml title="~/.bbot/config/bbot.yml"
# default == 10
dns:
  wildcard_tests: 20
```

If that doesn't work you can consider [blacklisting](#whitelists-and-blacklists) the offending domain.
