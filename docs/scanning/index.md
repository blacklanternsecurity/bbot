# Scanning Overview

## Scan Names

Every BBOT scan gets a random, mildly-entertaining name like **`demonic_jimmy`**. Output for that scan, including scan stats and any web screenshots, are saved to a folder by that name in `~/.bbot/scans`. The most recent 20 scans are kept, and older ones are removed.

If you don't want a random name, you can change it with `-n`. You can also change the location of BBOT's output with `-o`:

```bash
# save everything to the folder "my_scan" in the current directory
bbot -t evilcorp.com -f subdomain-enum -m gowitness -n my_scan -o .
```

If you reuse a scan name, BBOT will automatically append to your previous output files.

## Targets (`-t`), Seeds (`-s`), and Blacklists (`-b`)

BBOT uses three related concepts to control scope and drive a scan:

- **Targets (`-t`)** define what is **in-scope**. Active modules (e.g. `nuclei`, `portscan`) will only touch targets and their children.
- **Seeds (`-s`)** are the starting data that gets fed into modules. If you don't specify `-s`, **your targets are automatically used as seeds**.
- **Blacklists (`-b`)** define what is **never touched**. Anything matching the blacklist is excluded, even if it would otherwise be in-scope.

### Accepted Input Types

Targets, seeds, and blacklists all accept the same input types:

- `DNS_NAME` (`evilcorp.com`)
- `IP_ADDRESS` (`1.2.3.4`)
- `IP_RANGE` (`1.2.3.0/24`)
- `OPEN_TCP_PORT` (`192.168.0.1:80`)
- `URL` (`https://www.evilcorp.com`)
- `EMAIL_ADDRESS` (`bob@evilcorp.com`)
- `ASN` (`ASN:17178` or `AS17178`)
- `USERNAME` (`USER:bobsmith`)
- `ORG_STUB` (`ORG:evilcorp`)
- `FILESYSTEM` (`FILESYSTEM:/tmp/asdf`)
- `MOBILE_APP` (`MOBILE_APP:https://play.google.com/store/apps/details?id=com.evilcorp.app`)

Blacklists additionally accept **regex patterns** prefixed with `RE:` (see [Blacklist by Regex](#blacklist-by-regex)).

Note that BBOT only discriminates down to the host level. This means, for example, if you specify a URL `https://www.evilcorp.com` as the target, the scan will be *seeded* with that URL, but the scope of the scan will be the entire host, `www.evilcorp.com`. Other ports/URLs on that same host may also be scanned.

You can specify inputs directly on the command line, load them from files, or both:

```bash
$ cat targets.txt
4.3.2.1
10.0.0.2:80
1.2.3.0/24
evilcorp.com
evilcorp.co.uk
https://www.evilcorp.co.uk

# load targets from a file and from the command-line
$ bbot -t targets.txt fsociety.com 5.6.7.0/24 -m portscan
```

On start, BBOT automatically converts these inputs into [Events](events.md).

### Why Separate Targets and Seeds?

Separating targets from seeds lets you keep a tight scope while still allowing passive discovery outside of it. When BBOT discovers something out-of-scope via a seed, it will still report it, but active modules won't touch it.

For example, say your target has subdomains that resolve both inside and outside an IP range that defines your scope. You can set the IP range as the **target** and the domain as a **seed**:

```bash
bbot -t 192.168.1.0/24 -s evilcorp.com -f subdomain-enum -m nuclei
```

Any discovered `evilcorp.com` subdomains that resolve within `192.168.1.0/24` will be actively scanned by Nuclei. Others will be discovered and reported, but not touched by active modules.

### Blacklists

`-b` / `--blacklist` takes ultimate precedence. Anything in the blacklist is completely excluded from the scan, even if it would otherwise be in-scope based on your targets or seeds.

```bash
# Scan evilcorp.com, but exclude internal.evilcorp.com and its children
bbot -t evilcorp.com -b internal.evilcorp.com -f subdomain-enum -m portscan nuclei
```

#### Blacklist by Regex

Blacklists also accept regex patterns. These regexes are checked against the full URL, including the host and path.

To specify a regex, prefix the pattern with `RE:`. For example, to exclude all events containing "signout":

```bash
bbot -t evilcorp.com -b "RE:signout"
```

Note that this would blacklist both of the following events:

- `[URL]       http://evilcorp.com/signout.aspx`
- `[DNS_NAME]  signout.evilcorp.com`

If you only want to blacklist the URL, you could narrow the regex like so:

```bash
bbot -t evilcorp.com -b 'RE:signout\.aspx$'
```

Similar to targets, blacklists can be specified in your preset. The `spider` preset makes use of this to prevent the spider from following logout links:

```yaml title="spider.yml"
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

## Modules (`-m`)

To see a full list of modules and their descriptions, use `bbot -l` or see [List of Modules](../modules/list_of_modules.md).

Modules are the part of BBOT that does the work -- port scanning, subdomain brute-forcing, API querying, etc. Modules consume [Events](events.md) (`IP_ADDRESS`, `DNS_NAME`, etc.) from each other, process the data in a useful way, then emit the results as new events. You can enable individual modules with `-m`.

```bash
# Enable modules: portscan, sslcert, and http
bbot -t www.evilcorp.com -m portscan sslcert http
```

### Types of Modules

Modules fall into three categories:

- **Scan Modules**:
    - These make up the majority of modules. Examples are `portscan`, `sslcert`, `http`, etc. Enable with `-m`.
- **Output Modules**:
    - These output scan data to different formats/destinations. `human`, `json`, and `csv` are enabled by default. Enable others with `-om`. (See: [Output](output.md))
- **Internal Modules**:
    - These modules perform essential, common-sense tasks. They are always enabled, unless explicitly disabled via the config (e.g. `-c speculate=false`).
        - `aggregate`: Summarizes results at the end of a scan
        - `excavate`: Extracts useful data such as subdomains from webpages, etc.
        - `speculate`: Intelligently infers new events, e.g. `OPEN_TCP_PORT` from `URL` or `IP_ADDRESS` from `IP_NETWORK`.

For details in the inner workings of modules, see [How to Write a Module](../dev/module_howto.md).

## Flags (`-f`)

Flags are how BBOT categorizes its modules. In a way, you can think of them as groups. Flags let you enable a bunch of similar modules at the same time without having to specify them each individually. For example, `-f subdomain-enum` would enable every module with the `subdomain-enum` flag.

```bash
# list all subdomain-enum modules
bbot -f subdomain-enum -l
```

### Filtering Modules

Modules can be easily enabled/disabled based on their flags:

- `-f` Enable these flags (e.g. `-f subdomain-enum`)
- `-rf` Require modules to have this flag (e.g. `-rf passive`)
- `-ef` Exclude these flags (e.g. `-ef slow`)
- `-em` Exclude these individual modules (e.g. `-em ipneighbor`)
- `-lf` List all available flags

Every module is either `active` or `passive`. Some modules are additionally tagged `loud` (generates lots of traffic) or `invasive` (intrusive or potentially destructive). These can be useful for filtering. For example, if you wanted to enable subdomain enumeration modules but exclude loud ones, you could do:

```bash
# Enable subdomain-enum modules but exclude loud ones
bbot -t evilcorp.com -f subdomain-enum -ef loud
```

This is equivalent to requiring the passive flag:

```bash
# Enable subdomain-enum modules but only if they're also passive
bbot -t evilcorp.com -f subdomain-enum -rf passive
```

A single module can have multiple flags. For example, the `securitytrails` module is `passive`, `subdomain-enum`. Below is a full list of flags and their associated modules.

### List of Flags

<!-- BBOT MODULE FLAGS -->
| Flag             | # Modules   | Description                                                    | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|------------------|-------------|----------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| safe             | 99          | Non-intrusive and non-destructive                              | affiliates, aggregate, ajaxpro, anubisdb, apkpure, asn, aspnet_bin_exposure, azure_tenant, baddns, baddns_direct, baddns_zone, badsecrets, bevigil, bucket_amazon, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, bucket_hetzner, bucket_microsoft, bufferoverrun, builtwith, c99, censys_dns, censys_ip, certspotter, chaos, code_repository, credshed, crt, crt_db, dehashed, dnsbimi, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, docker_pull, dockerhub, emailformat, emails, excavate, filedownload, fingerprintx, fullhunt, git, git_clone, gitdumper, github_codesearch, github_org, github_usersearch, github_workflows, gitlab_com, gitlab_onprem, google_playstore, gowitness, graphql_introspection, hackertarget, http, hunt, hunterio, ip2location, ipstack, jadx, kreuzberg, leakix, myssl, newsletters, ntlm, oauth, otx, pgp, portfilter, postman, postman_download, rapiddns, reflected_parameters, retirejs, robots, securitytrails, securitytxt, shodan_dns, shodan_enterprise, shodan_idb, skymem, social, speculate, sslcert, subdomaincenter, subdomainradar, subdomains, trajan, trickest, trufflehog, unarchive, urlscan, viewdns, virustotal, wayback |
| passive          | 68          | Never connects to target systems                               | affiliates, aggregate, anubisdb, apkpure, asn, azure_tenant, bevigil, bucket_file_enum, bufferoverrun, builtwith, c99, censys_dns, censys_ip, certspotter, chaos, code_repository, credshed, crt, crt_db, dehashed, dnsbimi, dnscaa, dnsdumpster, dnstlsrpt, docker_pull, dockerhub, emailformat, excavate, fullhunt, git_clone, gitdumper, github_codesearch, github_org, github_usersearch, github_workflows, google_playstore, hackertarget, hunterio, ip2location, ipneighbor, ipstack, jadx, kreuzberg, leakix, myssl, otx, pgp, portfilter, postman, postman_download, rapiddns, securitytrails, shodan_dns, shodan_enterprise, shodan_idb, skymem, social, speculate, subdomaincenter, subdomainradar, trajan, trickest, trufflehog, unarchive, urlscan, viewdns, virustotal, wayback                                                                                                                                                                                                                                                                                                                                                                                                             |
| active           | 51          | Makes active connections to target systems                     | ajaxpro, aspnet_bin_exposure, baddns, baddns_direct, baddns_zone, badsecrets, bucket_amazon, bucket_digitalocean, bucket_firebase, bucket_google, bucket_hetzner, bucket_microsoft, bypass403, dnsbrute, dnsbrute_mutations, dnscommonsrv, dotnetnuke, filedownload, fingerprintx, generic_ssrf, git, gitlab_com, gitlab_onprem, gowitness, graphql_introspection, host_header, http, hunt, iis_shortnames, legba, lightfuzz, medusa, newsletters, ntlm, nuclei, oauth, paramminer_cookies, paramminer_getparams, paramminer_headers, portscan, reflected_parameters, retirejs, robots, securitytxt, sslcert, telerik, url_manipulation, wafw00f, webbrute, webbrute_shortnames, wpscan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| subdomain-enum   | 47          | Enumerates subdomains                                          | anubisdb, asn, azure_tenant, baddns_direct, baddns_zone, bevigil, bufferoverrun, builtwith, c99, censys_dns, certspotter, chaos, crt, crt_db, dnsbimi, dnsbrute, dnsbrute_mutations, dnscaa, dnscommonsrv, dnsdumpster, dnstlsrpt, fullhunt, github_codesearch, github_org, hackertarget, http, hunterio, ipneighbor, leakix, myssl, oauth, otx, postman, postman_download, rapiddns, securitytrails, securitytxt, shodan_dns, shodan_idb, sslcert, subdomaincenter, subdomainradar, subdomains, trickest, urlscan, virustotal, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| loud             | 21          | Generates a large amount of network traffic                    | bypass403, dnsbrute, dnsbrute_mutations, dotnetnuke, host_header, iis_shortnames, ipneighbor, legba, lightfuzz, medusa, nuclei, paramminer_cookies, paramminer_getparams, paramminer_headers, portscan, telerik, url_manipulation, wafw00f, webbrute, webbrute_shortnames, wpscan                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| code-enum        | 19          | Find public code repositories and search them for secrets etc. | apkpure, code_repository, docker_pull, dockerhub, git, git_clone, gitdumper, github_codesearch, github_org, github_usersearch, github_workflows, gitlab_com, gitlab_onprem, google_playstore, jadx, postman, postman_download, trajan, trufflehog                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| cloud-enum       | 16          | Enumerates cloud resources                                     | azure_tenant, baddns, baddns_direct, baddns_zone, bucket_amazon, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, bucket_hetzner, bucket_microsoft, dnsbimi, dnstlsrpt, http, oauth, securitytxt                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| web              | 16          | Non-intrusive web scan functionality                           | baddns, badsecrets, bucket_amazon, bucket_firebase, bucket_google, bucket_microsoft, filedownload, git, graphql_introspection, http, iis_shortnames, ntlm, oauth, robots, securitytxt, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| web-heavy        | 15          | More advanced web scanning functionality                       | ajaxpro, aspnet_bin_exposure, bucket_digitalocean, bucket_hetzner, bypass403, dotnetnuke, generic_ssrf, host_header, hunt, lightfuzz, reflected_parameters, retirejs, telerik, url_manipulation, webbrute_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| slow             | 10          | May take a long time to complete                               | bucket_digitalocean, bucket_hetzner, dnsbrute_mutations, docker_pull, fingerprintx, git_clone, gitdumper, paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| email-enum       | 9           | Enumerates email addresses                                     | dehashed, dnscaa, dnstlsrpt, emailformat, emails, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| affiliates       | 7           | Discovers affiliated hostnames/domains                         | affiliates, azure_tenant, builtwith, oauth, sslcert, trickest, viewdns                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| download         | 7           | Modules that download files, apps, or repositories             | apkpure, docker_pull, filedownload, git_clone, gitdumper, github_workflows, postman_download                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| invasive         | 7           | Intrusive or potentially destructive                           | dotnetnuke, generic_ssrf, legba, lightfuzz, medusa, nuclei, telerik                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| baddns           | 3           | Runs all modules from the DNS auditing tool BadDNS             | baddns, baddns_direct, baddns_zone                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| web-paramminer   | 3           | Discovers HTTP parameters through brute-force                  | paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| iis-shortnames   | 2           | Scans for IIS Shortname vulnerability                          | iis_shortnames, webbrute_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| portscan         | 2           | Discovers open ports                                           | portscan, shodan_idb                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| social-enum      | 2           | Enumerates social media                                        | http, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| service-enum     | 1           | Identifies protocols running on open ports                     | fingerprintx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| subdomain-hijack | 1           | Detects hijackable subdomains                                  | baddns                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| web-screenshots  | 1           | Takes screenshots of web pages                                 | gowitness                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
<!-- END BBOT MODULE FLAGS -->

## Dependencies

BBOT modules have external dependencies ranging from OS packages (`openssl`) to binaries (`nuclei`) to Python libraries (`wappalyzer`). When a module is enabled, installation of its dependencies happens at runtime with [Ansible](https://github.com/ansible/ansible). BBOT provides several command-line flags to control how dependencies are installed.

- `--no-deps` - Don't install module dependencies
- `--force-deps` - Force install all module dependencies
- `--retry-deps` - Try again to install failed module dependencies
- `--ignore-failed-deps` - Run modules even if they have failed dependencies
- `--install-all-deps` - Install dependencies for all modules (useful if you are provisioning a pentest system and want to install everything ahead of time)

For details on how Ansible playbooks are attached to BBOT modules, see [How to Write a Module](../dev/module_howto.md#module-dependencies).

## Scope

For pentesters and bug bounty hunters, staying in scope is extremely important. BBOT takes this seriously, meaning that active modules (e.g. `nuclei`) will only touch in-scope resources.

As described [above](#targets-t-seeds-s-and-blacklists-b), targets (`-t`) define what is in-scope and blacklists (`-b`) define what is excluded. Scope includes child subdomains by default -- for example, `-t evilcorp.com` puts `www.evilcorp.com`, `mail.evilcorp.com`, etc. in-scope automatically.

### Scope Distance

Since BBOT is recursive, it would quickly resort to scanning the entire internet without some kind of restraining mechanism. To solve this problem, every [event](events.md) discovered by BBOT is assigned a **Scope Distance**. Scope distance represents how far out from the main scope that data was discovered.

For example, if your target is `evilcorp.com`, `www.evilcorp.com` would have a scope distance of `0` (i.e. in-scope). If BBOT discovers that `www.evilcorp.com` resolves to `1.2.3.4`, `1.2.3.4` is one hop away, which means it would have a scope distance of `1`. If `1.2.3.4` has a PTR record that points to `ecorp.blob.core.windows.net`, `ecorp.blob.core.windows.net` is two hops away, so its scope distance is `2`.

Scope distance continues to increase the further out you get. Most modules (e.g. `nuclei` and `portscan`) only consume in-scope events. Certain other passive modules such as `asn` accept out to distance `1`. By default, DNS resolution happens out to a distance of `2`. Upon its discovery, any [event](events.md) that's determined to be in-scope (e.g. `www.evilcorp.com`) immediately becomes distance `0`, and the cycle starts over.

#### Displaying Out-of-scope Events

By default, BBOT only displays in-scope events (with a few exceptions such as `STORAGE_BUCKET`s). If you want to see more, you must increase the [config](configuration.md) value of `scope.report_distance`:

```bash
# display out-of-scope events up to one hop away from the main scope
bbot -t evilcorp.com -f subdomain-enum -c scope.report_distance=1
```

### Strict Scope

If you want to scan **_only_** that specific target hostname and none of its children, you can specify `--strict-scope`.

Note that `--strict-scope` only applies to targets, but not blacklists. This means that if you put `internal.evilcorp.com` in your blacklist, you can be sure none of its subdomains will be scanned, even when using `--strict-scope`.


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

If that doesn't work you can consider [blacklisting](#blacklists) the offending domain.
