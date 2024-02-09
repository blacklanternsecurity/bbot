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

### Filtering by Flag

Modules can be easily filtered based on their flags:

- `-f` Enable modules with this flag
- `-rf` Require modules to have this flag
- `-ef` Exclude modules with this flag
- `-em` Exclude these individual modules
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
| Flag             | # Modules   | Description                                   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|------------------|-------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| safe             | 76          | Non-intrusive, safe to run                    | affiliates, aggregate, ajaxpro, anubisdb, asn, azure_realm, azure_tenant, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, credshed, crobat, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, dnszonetransfer, emailformat, filedownload, fingerprintx, fullhunt, git, github_codesearch, github_org, gowitness, hackertarget, httpx, hunt, hunterio, iis_shortnames, internetdb, ip2location, ipstack, leakix, myssl, newsletters, nsec, ntlm, oauth, otx, passivetotal, pgp, postman, rapiddns, riddler, robots, secretsdb, securitytrails, shodan_dns, sitedossier, skymem, social, sslcert, subdomain_hijack, subdomaincenter, sublist3r, threatminer, urlscan, viewdns, virustotal, wappalyzer, wayback, zoomeye |
| passive          | 57          | Never connects to target systems              | affiliates, aggregate, anubisdb, asn, azure_realm, azure_tenant, bevigil, binaryedge, bucket_file_enum, builtwith, c99, censys, certspotter, chaos, columbus, credshed, crobat, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, emailformat, excavate, fullhunt, github_codesearch, github_org, hackertarget, hunterio, internetdb, ip2location, ipneighbor, ipstack, leakix, massdns, myssl, nsec, otx, passivetotal, pgp, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, skymem, social, speculate, subdomaincenter, sublist3r, threatminer, urlscan, viewdns, virustotal, wayback, zoomeye                                                                                                                                                                                                                                            |
| subdomain-enum   | 47          | Enumerates subdomains                         | anubisdb, asn, azure_realm, azure_tenant, bevigil, binaryedge, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, dnszonetransfer, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, nsec, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, sslcert, subdomain_hijack, subdomaincenter, subdomains, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                            |
| active           | 40          | Makes active connections to target systems    | ajaxpro, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dnszonetransfer, ffuf, ffuf_shortnames, filedownload, fingerprintx, generic_ssrf, git, gowitness, host_header, httpx, hunt, iis_shortnames, masscan, newsletters, nmap, ntlm, nuclei, oauth, paramminer_cookies, paramminer_getparams, paramminer_headers, robots, secretsdb, smuggler, sslcert, subdomain_hijack, telerik, url_manipulation, vhost, wafw00f, wappalyzer                                                                                                                                                                                                                                                                                                                                                               |
| web-thorough     | 29          | More advanced web scanning functionality      | ajaxpro, azure_realm, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, ffuf_shortnames, filedownload, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, nmap, ntlm, oauth, robots, secretsdb, smuggler, sslcert, subdomain_hijack, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| aggressive       | 19          | Generates a large amount of network traffic   | bypass403, dastardly, ffuf, ffuf_shortnames, generic_ssrf, host_header, ipneighbor, masscan, massdns, nmap, nuclei, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, telerik, url_manipulation, vhost, wafw00f                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| web-basic        | 17          | Basic, non-intrusive web scan functionality   | azure_realm, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, secretsdb, sslcert, subdomain_hijack, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| cloud-enum       | 11          | Enumerates cloud resources                    | azure_realm, azure_tenant, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, httpx, oauth, subdomain_hijack                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| affiliates       | 8           | Discovers affiliated hostnames/domains        | affiliates, azure_realm, azure_tenant, builtwith, oauth, sslcert, viewdns, zoomeye                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| slow             | 8           | May take a long time to complete              | bucket_digitalocean, dastardly, fingerprintx, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| email-enum       | 7           | Enumerates email addresses                    | dehashed, emailformat, emails, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| deadly           | 4           | Highly aggressive                             | dastardly, ffuf, nuclei, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| portscan         | 3           | Discovers open ports                          | internetdb, masscan, nmap                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| web-paramminer   | 3           | Discovers HTTP parameters through brute-force | paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| iis-shortnames   | 2           | Scans for IIS Shortname vulnerability         | ffuf_shortnames, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| report           | 2           | Generates a report at the end of the scan     | affiliates, asn                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| social-enum      | 2           | Enumerates social media                       | httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| service-enum     | 1           | Identifies protocols running on open ports    | fingerprintx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| subdomain-hijack | 1           | Detects hijackable subdomains                 | subdomain_hijack                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| web-screenshots  | 1           | Takes screenshots of web pages                | gowitness                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
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

By default, BBOT only displays in-scope events (with a few exceptions such as `STORAGE_BUCKET`s). If you want to see more, you must increase the [config](configuration.md) value of `scope_report_distance`:

```bash
# display out-of-scope events up to one hop away from the main scope
bbot -t evilcorp.com -f subdomain-enum -c scope_report_distance=1
```

### Strict Scope

If you want to scan **_only_** that specific target hostname and none of its children, you can specify `--strict-scope`.

Note that `--strict-scope` only applies to targets and whitelists, but not blacklists. This means that if you put `internal.evilcorp.com` in your blacklist, you can be sure none of its subdomains will be scanned, even when using `--strict-scope`.

### Whitelists and Blacklists

BBOT allows precise control over scope with whitelists and blacklists. These both use the same syntax as `--target`, meaning they accept the same event types, and you can specify an unlimited number of them, via a file, the CLI, or both.

`--whitelist` enables you to override what's in scope. For example, if you want to run nuclei against `evilcorp.com`, but stay only inside their corporate IP range of `1.2.3.0/24`, you can accomplish this like so:

```bash
# Seed scan with evilcorp.com, but restrict scope to 1.2.3.0/24
bbot -t evilcorp.com --whitelist 1.2.3.0/24 -f subdomain-enum -m nmap nuclei --allow-deadly
```

`--blacklist` takes ultimate precedence. Anything in the blacklist is completely excluded from the scan, even if it's in the whitelist.

```bash
# Scan evilcorp.com, but exclude internal.evilcorp.com and its children
bbot -t evilcorp.com --blacklist internal.evilcorp.com -f subdomain-enum -m nmap nuclei --allow-deadly
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
dns_wildcard_ignore:
  - evilcorp.com
  - evilcorp.co.uk
```

There are certain edge cases (such as with dynamic DNS rules) where BBOT's wildcard detection fails. In these cases, you can try increasing the number of wildcard checks in the config:

```yaml title="~/.bbot/config/bbot.yml"
# default == 10
dns_wildcard_tests: 20
```

If that doesn't work you can consider [blacklisting](#whitelists-and-blacklists) the offending domain.
