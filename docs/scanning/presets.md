# Presets

A Preset is a YAML file where you can put all the settings for a scan. That include targets, modules, and config options like API keys.

## Default Presets

BBOT has a ready-made collection of presets for common tasks like subdomain enumeration and web spidering. They live in `~/.bbot/presets`. You can enable them like this:

```bash
# do a subdomain enumeration 
bbot -t evilcorp.com -p subdomain-enum

# multiple presets - subdomain enumeration + web spider
bbot -t evilcorp.com -p subdomain-enum spider

# start with a preset but only enable modules that have the 'passive' flag
bbot -t evilcorp.com -p subdomain-enum -rf passive

# preset + manual config override
bbot -t www.evilcorp.com -p spider -c web_spider_distance=10

# list available presets
bbot -lp
```

You can also build on the default presets, or create your own. Here's an example of a custom preset that builds on `subdomain-enum`:

```yaml title="my_subdomains.yml"
description: Do a subdomain enumeration + basic web scan + nuclei

target:
  - evilcorp.com

include:
  - subdomain-enum
  - web-basic

modules:
  # enable nuclei in addition to the other modules
  - nuclei

config:
  modules:
    securitytrails:
      api_key: 21a270d5f59c9b05813a72bb41707266
    virustotal:
      api_key: 4f41243847da693a4f356c0486114bc6
```

To execute your custom preset, you do:

```bash
bbot -p ./my_subdomains.yml
```

## Preset Load Order

When you enable multiple presets, the order matters. In the case of a conflict, the last preset will always win. This means, for example, if you have a custom preset called `my_spider` that sets `web_spider_distance` to 1:

```yaml title="my_spider.yml"
web_spider_distance: 1
```

...and you enable it alongside the default `spider` preset in this order:

```bash
bbot -t evilcorp.com -p ./my_spider.yml spider
```

...the value of `web_spider_distance` will be overridden by `spider`. To ensure this doesn't happen, you would want to switch the order of the presets:

```bash
bbot -t evilcorp.com -p spider ./my_spider.yml
```

## Validating Presets

To make sure BBOT is configured the way you expect, you can always check the `--current-preset` to show the final verison of the config that will be used when BBOT executes:

```bash
# verify the preset is what you want
bbot -p ./mypreset.yml --current-preset
```

## Advanced Usage

BBOT Presets support advanced features like environment variable substitution and custom conditions.

### Environment Variables

You can insert environment variables into your preset like this: `${env:<variable>}`:

```yaml title="my_nuclei.yml"
description: Do a nuclei scan

target:
  - evilcorp.com

modules:
  - nuclei

config:
  modules:
    nuclei:
      # allow the nuclei templates to be specified at runtime via an environment variable
      templates: ${env:NUCLEI_TEMPLATES}
```

```bash
NUCLEI_TEMPLATES=apache,nginx bbot -p ./my_nuclei.yml
```

### Conditions

Sometimes, you might need to add custom logic to a preset. BBOT supports this via `conditions`. The `conditions` attribute allows you to specify a list of custom conditions that will be evaluated before the scan starts. This is useful for performing last-minute sanity checks, or changing the behavior of the scan based on custom criteria.

```yaml title="my_preset.yml"
description: Abort if nuclei templates aren't specified

modules:
  - nuclei

conditions:
  - |
    {% if not config.modules.nuclei.templates %}
      {{ abort("Don't forget to set your templates!") }}
    {% endif %}
```

```yaml title="my_preset.yml"
description: Enable ffuf but only if the web spider isn't enabled

modules:
  - ffuf

conditions:
  - |
    {% if config.web_spider_distance > 0 and config.web_spider_depth > 0 %}
      {{ warn("Disabling ffuf because the web spider is enabled") }}
      {{ preset.exclude_module("ffuf") }}
    {% endif %}
```

Conditions use [Jinja](https://palletsprojects.com/p/jinja/), which means they can contain Python code. They run inside a sandboxed environment which has access to the following variables:

- `preset` - the current preset object
- `config` - the current config (an alias for `preset.config`)
- `warn(message)` - display a custom warning message to the user
- `abort(message)` - abort the scan with an optional message

If you aren't able to accomplish what you want with conditions, or if you need access to a new variable/function, please let us know on [Github](https://github.com/blacklanternsecurity/bbot/issues/new/choose).


## List of Presets

Here is a full list of BBOT's default presets:

<!-- BBOT PRESETS -->
| Preset         | Category     | Description                                                      | # Modules   | Modules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
|----------------|--------------|------------------------------------------------------------------|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| cloud-enum     | default      | Enumerate cloud resources such as storage buckets, etc.          | 52          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_zone, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                         |
| code-enum      | default      | Enumerate Git repositories, Docker images, etc.                  | 3           | dockerhub, github_org, social                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| dirbust-heavy  | web_advanced | Recursive web directory brute-force (aggressive)                 | 5           | ffuf, ffuf_shortnames, httpx, iis_shortnames, wayback                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| dirbust-light  | web_advanced | Basic web directory brute-force (surface-level directories only) | 4           | ffuf, ffuf_shortnames, httpx, iis_shortnames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| email-enum     | default      | Enumerate email addresses from APIs, web crawling, etc.          | 6           | dehashed, emailformat, hunterio, pgp, skymem, sslcert                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| kitchen-sink   | default      | Everything everywhere all at once                                | 70          | anubisdb, asn, azure_realm, azure_tenant, baddns, baddns_zone, badsecrets, bevigil, binaryedge, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_file_enum, bucket_firebase, bucket_google, builtwith, c99, censys, certspotter, chaos, columbus, crt, dehashed, digitorus, dnscommonsrv, dnsdumpster, dockerhub, emailformat, ffuf, ffuf_shortnames, filedownload, fullhunt, git, github_codesearch, github_org, hackertarget, httpx, hunterio, iis_shortnames, internetdb, ipneighbor, leakix, massdns, myssl, ntlm, oauth, otx, paramminer_cookies, paramminer_getparams, paramminer_headers, passivetotal, pgp, postman, rapiddns, riddler, robots, secretsdb, securitytrails, shodan_dns, sitedossier, skymem, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wappalyzer, wayback, zoomeye |
| paramminer     | web_advanced | Discover new web parameters via brute-force                      | 4           | httpx, paramminer_cookies, paramminer_getparams, paramminer_headers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| secrets-enum   | default      |                                                                  | 0           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| spider         | default      | Recursive web spider                                             | 1           | httpx                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| subdomain-enum | default      | Enumerate subdomains via APIs, brute-force                       | 45          | anubisdb, asn, azure_realm, azure_tenant, baddns_zone, bevigil, binaryedge, builtwith, c99, censys, certspotter, chaos, columbus, crt, digitorus, dnscommonsrv, dnsdumpster, fullhunt, github_codesearch, github_org, hackertarget, httpx, hunterio, internetdb, ipneighbor, leakix, massdns, myssl, oauth, otx, passivetotal, postman, rapiddns, riddler, securitytrails, shodan_dns, sitedossier, social, sslcert, subdomaincenter, threatminer, urlscan, virustotal, wayback, zoomeye                                                                                                                                                                                                                                                                                                                                     |
| web-basic      | default      | Quick web scan                                                   | 17          | azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_firebase, bucket_google, filedownload, git, httpx, iis_shortnames, ntlm, oauth, robots, secretsdb, sslcert, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| web-thorough   | default      | Aggressive web scan                                              | 30          | ajaxpro, azure_realm, baddns, badsecrets, bucket_amazon, bucket_azure, bucket_digitalocean, bucket_firebase, bucket_google, bypass403, dastardly, dotnetnuke, ffuf_shortnames, filedownload, generic_ssrf, git, host_header, httpx, hunt, iis_shortnames, nmap, ntlm, oauth, robots, secretsdb, smuggler, sslcert, telerik, url_manipulation, wappalyzer                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
<!-- END BBOT PRESETS -->

<details><summary>`subdomain-enum`</summary>

```yaml title="~/.bbot/presets/subdomain-enum.yml"
description: Enumerate subdomains via APIs, brute-force

flags:
  - subdomain-enum

output_modules:
  - subdomains

```

</details>
