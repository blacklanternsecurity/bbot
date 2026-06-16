# Tips and Tricks

Below are some helpful tricks to help you in your adventures.

## Change Verbosity During Scan
Press enter during a BBOT scan to change the log level. This will allow you to see debugging messages, etc.

<img src="https://user-images.githubusercontent.com/20261699/224358855-9411cdc6-68a9-4cc4-828f-e30e4766101a.gif" style="max-width: 45em !important"/>

## Kill Individual Module During Scan
Sometimes a certain module can get stuck or slow down the scan. If this happens and you want to kill it, just type "`kill <module>`" in the terminal and press enter. This will kill and disable the module for the rest of the scan.

You can also kill multiple modules at a time by specifying them in a space or comma-separated list:

```bash
kill http sslcert
```

<img src="https://github.com/blacklanternsecurity/bbot/assets/20261699/61ad7123-8879-4c86-afdd-e96d7264b67c" style="max-width: 45em !important"/>

## Common Config Changes

### Speed Up Slow Modules

BBOT modules can be parallelized so that more than one instance runs at a time. By default, many modules are already set to reasonable defaults:

```python
class baddns(BaseModule):
    module_threads = 8
```

To override this, you can set a module's `module_threads` in the config:

```bash
# increase baddns threads to 20
bbot -t evilcorp.com -m baddns -c modules.baddns.module_threads=20
```

### Boost DNS Brute-force Speed

If you have a fast internet connection or are running BBOT from a cloud VM, you can speed up subdomain enumeration by cranking the threads for `massdns`. The default is `1000`, which is about 1MB/s of DNS traffic:

```bash
# massdns with 5000 resolvers, about 5MB/s
bbot -t evilcorp.com -f subdomain-enum -c dns.brute_threads=5000
```

### Speed Up Scans with More DNS Resolvers

By far the most effective way to speed up a BBOT scan is to **add more resolvers to `/etc/resolv.conf`**. BBOT's DNS engine (blastdns) spins up ten workers per resolver, so more resolvers = more parallelism = faster scans.

For OSINT, it's critical that every resolver is **unfiltered**. Specialized resolvers that try to block ads, malicious domains, etc. will intentionally omit results. Below is a sample `/etc/resolv.conf` with 11 unfiltered public resolvers:

```conf
--8<-- "docs/data/resolv-sample.conf"
```

Copy this to `/etc/resolv.conf` (or append the `nameserver` lines to your existing config). With all 11 resolvers, blastdns will run 110 workers in parallel instead of the typical 10-30 you get from a default OS config.

!!! tip
    If your system uses `systemd-resolved` or `resolvconf`, you may need to configure the upstream forwarders there instead of editing `/etc/resolv.conf` directly.

### Web Spider

The web spider is great for finding juicy data like subdomains, email addresses, and javascript secrets buried in webpages. However since it can lengthen the duration of a scan, it's disabled by default. To enable it, use one of the built-in spider presets:

- **`spider`** -- follows links up to distance 2, depth 4, 25 links per page. Includes a blacklist to avoid following logout links.
- **`spider-heavy`** -- more aggressive: distance 4, depth 6, 50 links per page.

```bash
# spider www.evilcorp.com
bbot -t www.evilcorp.com -p spider

# pair with subdomain enumeration
bbot -t evilcorp.com -p subdomain-enum spider

# use the heavier spider
bbot -t evilcorp.com -p subdomain-enum spider-heavy
```

If you need custom settings, the spider is controlled with three config values:

- `web.spider_distance` (`0` == disabled, default: `0`): the maximum number of links that can be followed in a row.
- `web.spider_depth` (default: `1`): the maximum directory depth allowed.
- `web.spider_links_per_page` (default: `25`): the maximum number of links per page that can be followed.

```bash
# custom spider settings on the command line
bbot -t www.evilcorp.com -m http -c web.spider_distance=3 web.spider_depth=5
```

### Exclude CDNs from Port Scan

Use `--exclude-cdn` to filter out unwanted open ports from CDNs and WAFs, e.g. Cloudflare. You can also customize the criteria by setting `modules.portfilter.cdn_tags`. By default, only open ports with `cdn-*` tags are filtered, but you can include all cloud providers by setting `cdn_tags` to `cdn,cloud`:

```bash
bbot -t evilcorp.com --exclude-cdn -c modules.portfilter.cdn_tags=cdn,cloud
```

Additionally, you can customize the allowed ports by setting `modules.portscan.allowed_cdn_ports`.

```bash
bbot -t evilcorp.com --exclude-cdn -c modules.portfilter.allowed_cdn_ports=80,443,8443
```

Example preset:

```yaml title="skip_cdns.yml"
modules:
  - portfilter

config:
  modules:
    portfilter:
      cdn_tags: cdn-,cloud-
      allowed_cdn_ports: 80,443,8443
```

```bash
bbot -t evilcorp.com -p skip_cdns.yml
```

### Custom HTTP Proxy

Web pentesters may appreciate BBOT's ability to quickly populate Burp Suite site maps for all subdomains in a target. If your scan includes gowitness, this will capture the traffic as if you manually visited each website in your browser -- including auxiliary web resources and javascript API calls. To accomplish this, set the `web.http_proxy` config option like so:

```bash
# enumerate subdomains, take web screenshots, proxy through Burp
bbot -t evilcorp.com -f subdomain-enum -m gowitness -c web.http_proxy=http://127.0.0.1:8080
```

### Display `HTTP_RESPONSE` Events

BBOT's `http` module emits `HTTP_RESPONSE` events, but by default they're hidden from output. These events contain the full raw HTTP body along with headers, etc. If you want to see them, you can modify `omit_event_types` in the config:

```yaml title="~/.bbot/config/bbot.yml"
omit_event_types:
  - URL_UNVERIFIED
  # - HTTP_RESPONSE
```

### Display Out-of-scope Events
By default, BBOT only shows in-scope events (with a few exceptions for things like storage buckets). If you want to see events that BBOT is emitting internally (such as for DNS resolution, etc.), you can increase `scope.report_distance` in the config or on the command line like so:
~~~bash
# display events up to scope distance 2 (default == 0)
bbot -f subdomain-enum -t evilcorp.com -c scope.report_distance=2
~~~

### Speed Up Scans with `--fast-mode`

If you have a ready list of hosts/urls and just want to scan them as fast as possible without any extra discovery, use `--fast-mode`. It's a CLI alias for `--preset fast`, which disables non-essential speculation and DNS resolution:

```yaml
--8<-- "bbot/presets/fast.yml"
```

If you already have a list of discovered targets (e.g. URLs) and don't need DNS-based scope checks, you can go further by completely disabling DNS resolution:

~~~bash
# completely disable DNS resolution
bbot -m http gowitness -t urls.txt -c dns.disable=true
~~~

Note that the above setting _completely_ disables DNS, meaning even `A` and `AAAA` records are not resolved. This can cause problems if you're using an IP whitelist or blacklist. In this case, you'll want to use `dns.minimal` instead:

~~~bash
# only resolve A and AAAA records
bbot -m http gowitness -t urls.txt -c dns.minimal=true
~~~

## FAQ

### What is `URL_UNVERIFIED`?

`URL_UNVERIFIED` events are URLs that haven't yet been visited by `http`. Once `http` visits them, it reraises them as `URL`s, tagged with their resulting status code.

For example, when [`excavate`](index.md/#types-of-modules) gets an `HTTP_RESPONSE` event, it extracts links from the raw HTTP response as `URL_UNVERIFIED`s and then passes them back to `http` to be visited.

By default, `URL_UNVERIFIED`s are hidden from output. If you want to see all of them including the out-of-scope ones, you can do it by changing `omit_event_types` and `scope.report_distance` in the config like so:

```bash
# visit www.evilcorp.com and extract all the links
bbot -t www.evilcorp.com -m http -c omit_event_types=[] scope.report_distance=2
```

### Can I crank up the threads for a module to make it go faster?

Yes, you can customize the threads for any module by setting `module_threads` like so:

```bash
bbot -t evilcorp.com -m sslcert -c modules.sslcert.module_threads=50
```

`module_threads` is one of several [universal module options](./configuration.md) that can be applied to any module.

[Next Up: Advanced Usage -->](./advanced.md){ .md-button .md-button--primary }
