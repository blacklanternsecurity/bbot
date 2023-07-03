# Scanning Overview

<video controls="" autoplay="" name="media"><source src="https://github-production-user-asset-6210df.s3.amazonaws.com/20261699/245941416-ebf2a81e-7530-4a9e-922d-4e62eb949f35.mp4" type="video/mp4"></video>

*A BBOT scan in real-time - visualization courtesy of [VivaGraphJS](https://github.com/blacklanternsecurity/bbot-vivagraphjs)*


## Targets (`-t`)

Targets declare what's in-scope, and seed a scan with initial data. BBOT accepts an unlimited number of targets. They can be any of the following:

- `DNS_NAME` (`evilcorp.com`)
- `IP_ADDRESS` (`1.2.3.4`)
- `IP_RANGE` (`1.2.3.0/24`)
- `URL` (`https://www.evilcorp.com`)

You can specify targets directly on the command line, load them from files, or both! For example:

~~~bash
$ cat targets.txt
4.3.2.1
1.2.3.0/24
evilcorp.com
evilcorp.co.uk
https://www.evilcorp.co.uk

# load targets from a file and from the command-line
$ bbot -t targets.txt fsociety.com 5.6.7.0/24 -m nmap
~~~

On start, BBOT automatically converts Targets into [Events](./events).

## Scope

For pentesters and bug bounty hunters, staying in scope is extremely important. BBOT takes this seriously, meaning that active modules (e.g. `nuclei`) will only touch in-scope resources.

By default, whatever you specify with `-t` becomes in-scope. This includes child subdomains. For example, if you specify `-t evilcorp.com`, any subdomains (`www.evilcorp.com`, `mail.evilcorp.com`, etc.) become in-scope.

### Scope Distance

Since BBOT is recursive, it would quickly resort to scannning the entire internet if left unscoped. To solve this problem, every [event](./events) discovered by BBOT is assigned a **Scope Distance**. Scope distance represents how far out from the main scope that data was discovered.

For example, if your target is `evilcorp.com` and `evilcorp.com` resolves to `1.2.3.4`, `evilcorp.com` itself would have a scope distance of `0` (i.e. in-scope) and `1.2.3.4` would have a scope distance of `1`. 

Scope distance continues to increase the further out you get. Most modules (e.g. `nuclei` and `nmap`) only consume in-scope events. Certain other passive modules such as `asn` accept out to distance `1`. By default, DNS resolution happens out to a distance of `2`. Any [event](./events) that's determined to be in-scope (i.e. `www.evilcorp.com`) immediately becomes distance `0`, and the cycle of discovery starts again.

### Strict Scope

If you want to scan ***only*** that specific target hostname and none of its children, you can specify `--strict-scope`.

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

## Modules (`-m`)

To see a full list of modules and their descriptions, use `bbot -l` or see [Modules Table](./modules_table).

Modules are the part of BBOT that does the work -- port scanning, subdomain brute-forcing, API querying, etc. Modules consume [Events](../events/) (`IP_ADDRESS`, `DNS_NAME`, etc.) from each other, process the data in a useful way, then emit the results as new events. You can enable individual modules with `-m`.

```bash
# Enable modules: nmap, sslcert, and httpx
bbot -t www.evilcorp.com -m nmap sslcert httpx
```

### Types of Modules

Modules fall into three categories:

- **Scan Modules**:
    - These make up the majority of modules. Examples are `nmap`, `sslcert`, `httpx`, etc. Enable with `-m`.
- **Output Modules**:
    - These output scan data to different formats/destinations. `human`, `json`, and `csv` are enabled by default. Enable others with `-om`. (See: [Output](./output))
- **Internal Modules**:
    - These modules perform essential, common-sense tasks. They are always enabled, unless explicitly disabled via the config (e.g. `-c speculate=false`).
        - `aggregate`: Summarizes results at the end of a scan
        - `excavate`: Extracts useful data such as subdomains from webpages, etc.
        - `speculate`: Intelligently infers new events, e.g. `OPEN_TCP_PORT` from `URL` or `IP_ADDRESS` from `IP_NETWORK`.

For details in the inner workings of modules, see [Creating a Module](../contribution/module_creation/).

## Flags (`-f`)

Flags are how BBOT categorizes its modules. In a way, you can think of them as groups. Flags let you enable a bunch of similar modules at the same time without having to specify them each individually. For example, `-f subdomain-enum` would enable all the modules having the `subdomain-enum` flag.

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
| Flag             | # Modules   | Description   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|------------------|-------------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| safe             | 58          |               | affiliates, aggregate, anubisdb, asn, azure_tenant, badsecrets, bevigil, binaryedge, bucket_aws, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_gcp, builtwith, c99, censys, certspotter, columbus, crobat, crt, dnscommonsrv, dnsdumpster, dnszonetransfer, emailformat, fingerprintx, fullhunt, git, github, gowitness, hackertarget, httpx, hunt, hunterio, iis_shortnames, ipstack, leakix, ntlm, otx, passivetotal, pgp, rapiddns, riddler, robots, secretsdb, securitytrails, shodan_dns, skymem, social, sslcert, subdomain_hijack, sublist3r, threatminer, urlscan, viewdns, virustotal, wappalyzer, wayback, zoomeye |
| passive          | 42          |               | affiliates, aggregate, anubisdb, asn, azure_tenant, bevigil, binaryedge, builtwith, c99, censys, certspotter, columbus, crobat, crt, dnscommonsrv, dnsdumpster, emailformat, excavate, fullhunt, github, hackertarget, hunterio, ipneighbor, ipstack, leakix, massdns, otx, passivetotal, pgp, rapiddns, riddler, securitytrails, shodan_dns, skymem, speculate, sublist3r, threatminer, urlscan, viewdns, virustotal, wayback, zoomeye                                                                                                                                                                                                   |
| active           | 37          |               | badsecrets, bucket_aws, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_gcp, bypass403, dnszonetransfer, ffuf, ffuf_shortnames, fingerprintx, generic_ssrf, git, gowitness, host_header, httpx, hunt, iis_shortnames, masscan, naabu, nmap, ntlm, nuclei, paramminer_cookies, paramminer_getparams, paramminer_headers, robots, secretsdb, smuggler, social, sslcert, subdomain_hijack, telerik, url_manipulation, vhost, wafw00f, wappalyzer                                                                                                                                                                                  |
| subdomain-enum   | 35          |               | anubisdb, asn, azure_tenant, bevigil, binaryedge, builtwith, c99, censys, certspotter, columbus, crt, dnscommonsrv, dnsdumpster, dnszonetransfer, fullhunt, github, hackertarget, httpx, hunterio, ipneighbor, leakix, massdns, otx, passivetotal, rapiddns, riddler, securitytrails, shodan_dns, sslcert, subdomain_hijack, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                           |
| web-thorough     | 25          |               | badsecrets, bucket_aws, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_gcp, bypass403, ffuf_shortnames, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, naabu, nmap, ntlm, robots, secretsdb, smuggler, sslcert, subdomain_hijack, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                         |
| aggressive       | 19          |               | bypass403, ffuf, ffuf_shortnames, generic_ssrf, host_header, ipneighbor, masscan, massdns, naabu, nmap, nuclei, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, telerik, url_manipulation, vhost, wafw00f                                                                                                                                                                                                                                                                                                                                                                                                         |
| web-basic        | 15          |               | badsecrets, bucket_aws, bucket_azure, bucket_firebase, bucket_gcp, git, httpx, hunt, iis_shortnames, ntlm, robots, secretsdb, sslcert, subdomain_hijack, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| slow             | 9           |               | bucket_digitalocean, fingerprintx, massdns, paramminer_cookies, paramminer_getparams, paramminer_headers, smuggler, telerik, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| cloud-enum       | 7           |               | bucket_aws, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_gcp, httpx, subdomain_hijack                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| affiliates       | 6           |               | affiliates, azure_tenant, builtwith, sslcert, viewdns, zoomeye                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| email-enum       | 6           |               | censys, emailformat, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| deadly           | 3           |               | ffuf, nuclei, vhost                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| portscan         | 3           |               | masscan, naabu, nmap                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| web-paramminer   | 3           |               | paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| report           | 2           |               | affiliates, asn                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| social-enum      | 2           |               | httpx, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| iis-shortnames   | 2           |               | ffuf_shortnames, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| subdomain-hijack | 1           |               | subdomain_hijack                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| web-screenshots  | 1           |               | gowitness                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| service-enum     | 1           |               | fingerprintx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
<!-- END BBOT MODULE FLAGS -->
