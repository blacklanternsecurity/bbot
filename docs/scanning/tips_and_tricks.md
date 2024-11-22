# Tips and Tricks

Below are some helpful tricks to help you in your adventures.

## Change Verbosity During Scan
Press enter during a BBOT scan to change the log level. This will allow you to see debugging messages, etc.

<img src="https://user-images.githubusercontent.com/20261699/224358855-9411cdc6-68a9-4cc4-828f-e30e4766101a.gif" style="max-width: 45em !important"/>

## Kill Individual Module During Scan
Sometimes a certain module can get stuck or slow down the scan. If this happens and you want to kill it, just type "`kill <module>`" in the terminal and press enter. This will kill and disable the module for the rest of the scan.

You can also kill multiple modules at a time by specifying them in a space or comma-separated list:

```bash
kill httpx sslcert
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

### Web Spider

The web spider is great for finding juicy data like subdomains, email addresses, and javascript secrets buried in webpages. However since it can lengthen the duration of a scan, it's disabled by default. To enable the web spider, you must increase the value of `web.spider_distance`.

The web spider is controlled with three config values:

- `web.spider_depth` (default: `1`: the maximum directory depth allowed. This is to prevent the spider from delving too deep into a website.
- `web.spider_distance` (`0` == all spidering disabled, default: `0`): the maximum number of links that can be followed in a row. This is designed to limit the spider in cases where `web.spider_depth` fails (e.g. for an ecommerce website with thousands of base-level URLs).
- `web.spider_links_per_page` (default: `25`): the maximum number of links per page that can be followed. This is designed to save you in cases where a single page has hundreds or thousands of links.

Here is a typical example:

```yaml title="spider.yml"
config:
  web:
    spider_depth: 2
    spider_distance: 2
    spider_links_per_page: 25
```

```bash
# run the web spider against www.evilcorp.com
bbot -t www.evilcorp.com -m httpx -c spider.yml
```

You can also pair the web spider with subdomain enumeration:

```bash
# spider every subdomain of evilcorp.com
bbot -t evilcorp.com -f subdomain-enum -c spider.yml
```

### Exclude CDNs from Port Scan

If you want to exclude CDNs (e.g. Cloudflare) from port scanning, you can set the `allowed_cdn_ports` config option in the `portscan` module. For example, to allow only port 80 (HTTP) and 443 (HTTPS), you can do the following:

```bash
bbot -t evilcorp.com -m portscan -c modules.portscan.allowed_cdn_ports=80,443
```

By default, if you set `allowed_cdn_ports`, it will skip only providers marked as CDNs. If you want to skip cloud providers as well, you can set `cdn_tags`, which is a comma-separated list of tags to skip (matched against the beginning of each tag).

```bash
bbot -t evilcorp.com -m portscan -c modules.portscan.allowed_cdn_ports=80,443 modules.portscan.cdn_tags=cdn-,cloud-
```

...or via a preset:

```yaml title="skip_cdns.yml"
modules:
  - portscan

config:
  modules:
    portscan:
      allowed_cdn_ports: 80,443
      cdn_tags: cdn-,cloud-
```

```bash
bbot -t evilcorp.com -p skip_cdns.yml
```

### Ingest BBOT Data Into SIEM (Elastic, Splunk)

If your goal is to run a BBOT scan and later feed its data into a SIEM such as Elastic, be sure to enable this option when scanning:

```bash
bbot -t evilcorp.com -c modules.json.siem_friendly=true
```

This ensures the `.data` event attribute is always the same type (a dictionary), by nesting it like so:
```json
{
  "type": "DNS_NAME",
  "data": {
    "DNS_NAME": "blacklanternsecurity.com"
  }
}
```

### Custom HTTP Proxy

Web pentesters may appreciate BBOT's ability to quickly populate Burp Suite site maps for all subdomains in a target. If your scan includes gowitness, this will capture the traffic as if you manually visited each website in your browser -- including auxiliary web resources and javascript API calls. To accomplish this, set the `web.http_proxy` config option like so:

```bash
# enumerate subdomains, take web screenshots, proxy through Burp
bbot -t evilcorp.com -f subdomain-enum -m gowitness -c web.http_proxy=http://127.0.0.1:8080
```

### Display `HTTP_RESPONSE` Events

BBOT's `httpx` module emits `HTTP_RESPONSE` events, but by default they're hidden from output. These events contain the full raw HTTP body along with headers, etc. If you want to see them, you can modify `omit_event_types` in the config:

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

### Speed Up Scans By Disabling DNS Resolution

If you already have a list of discovered targets (e.g. URLs), you can speed up the scan by skipping BBOT's DNS resolution. You can do this by setting `dns.disable` to `true`:

~~~bash
# completely disable DNS resolution
bbot -m httpx gowitness wappalyzer -t urls.txt -c dns.disable=true
~~~

Note that the above setting _completely_ disables DNS resolution, meaning even `A` and `AAAA` records are not resolved. This can cause problems if you're using an IP whitelist or blacklist. In this case, you'll want to use `dns.minimal` instead:

~~~bash
# only resolve A and AAAA records
bbot -m httpx gowitness wappalyzer -t urls.txt -c dns.minimal=true
~~~

## FAQ

### What is `URL_UNVERIFIED`?

`URL_UNVERIFIED` events are URLs that haven't yet been visited by `httpx`. Once `httpx` visits them, it reraises them as `URL`s, tagged with their resulting status code.

For example, when [`excavate`](index.md/#types-of-modules) gets an `HTTP_RESPONSE` event, it extracts links from the raw HTTP response as `URL_UNVERIFIED`s and then passes them back to `httpx` to be visited.

By default, `URL_UNVERIFIED`s are hidden from output. If you want to see all of them including the out-of-scope ones, you can do it by changing `omit_event_types` and `scope.report_distance` in the config like so:

```bash
# visit www.evilcorp.com and extract all the links
bbot -t www.evilcorp.com -m httpx -c omit_event_types=[] scope.report_distance=2
```
