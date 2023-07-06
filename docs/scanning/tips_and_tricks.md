# Tips and Tricks

Below are some helpful tricks to help you in your adventures.

## Change Verbosity During Scan
Press enter during a BBOT scan to change the log level. This will allow you to see debugging messages, etc.

<img src="https://user-images.githubusercontent.com/20261699/224358855-9411cdc6-68a9-4cc4-828f-e30e4766101a.gif" style="max-width: 45em !important"/>

## Common Config Changes

### Custom HTTP Proxy

Web pentesters may appreciate the ability to proxy a BBOT scan through Burp Suite. When executed with gowitness, this can even capture auxiliary web resources, API calls, etc. To accomplish this, set the `http_proxy` config option like so:

```bash
# enumerate subdomains, take web screenshots
bbot -t evilcorp.com -f subdomain-enum -m gowitness -c http_proxy=http://127.0.0.1:8080
```

### Display `HTTP_RESPONSE` Events

BBOT's `httpx` module emits `HTTP_RESPONSE` events, but by default they're hidden from output. These events contain the full raw HTTP body along with headers, etc. If you want to see them, you can modify `omit_event_types` in the config:

**`~/.config/bbot/bbot.yml`:**
```yaml
omit_event_types:
  - URL_UNVERIFIED
  # - HTTP_RESPONSE
```

### Display Out-of-scope Events
By default, BBOT only shows in-scope events (with a few exceptions for things like storage buckets). If you want to see events that BBOT is emitting internally (such as for DNS resolution, etc.), you can increase `scope_report_distance` in the config or on the command line like so:
~~~bash
bbot -f subdomain-enum -t evilcorp.com -c scope_report_distance=2
~~~

### Speed Up Scans By Disabling DNS Resolution
If you already have a list of discovered targets (e.g. URLs), you can speed up the scan by skipping BBOT's DNS resolution. You can do this by setting `dns_resolution` to `false`.
~~~bash
bbot -m httpx gowitness wappalyzer -t urls.txt -c dns_resolution=false
~~~

## FAQ

### What is `URL_UNVERIFIED`?

`URL_UNVERIFIED` events are URLs that haven't yet been visited by `httpx`. Once `httpx` visits them, it reraises them as `URL`s, tagged with their resulting status code.

For example, when [`excavate`](../#types-of-modules) gets an `HTTP_RESPONSE` event, it extracts links from the raw HTTP response as `URL_UNVERIFIED`s and then passes them back to `httpx` to be visited.

By default, `URL_UNVERIFIED`s are hidden from output. If you want to see all of them including the out-of-scope ones, you can do it by changing `omit_event_types` and `scope_report_distance` in the config like so:

```bash
# visit www.evilcorp.com and extract all the links
bbot -t www.evilcorp.com -m httpx -c omit_event_types=[] scope_report_distance=2
```
