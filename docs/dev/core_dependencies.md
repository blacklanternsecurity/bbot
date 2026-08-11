# Core Dependencies

BBOT is built on top of several purpose-built libraries, most of which are maintained by [Black Lantern Security](https://github.com/blacklanternsecurity). Understanding these will help you navigate the codebase and avoid reinventing things that already exist.

Libraries marked with **BLS** are maintained by us.

## blasthttp (BLS)

[blasthttp](https://github.com/blacklanternsecurity/blasthttp) is a Rust-backed HTTP client built for speed. It handles all of BBOT's outbound HTTP traffic, including module API calls, web spidering, and brute-forcing.

Module authors don't typically interact with blasthttp directly. Instead, use `self.helpers.request()`:

```python
response = await self.helpers.request("https://example.com/api")
if response and response.status_code == 200:
    data = response.json()
```

The shared blasthttp client is accessible at `self.helpers.blasthttp` and respects the global `web.http_rate_limit` config.

## blastdns (BLS)

[blastdns](https://github.com/blacklanternsecurity/blastdns) is a Rust-backed async DNS resolver. It powers all of BBOT's DNS resolution with built-in caching, retries, and per-resolver parallelism. BBOT spins up multiple workers per resolver in `/etc/resolv.conf`, so adding more resolvers directly speeds up scans.

Accessed via `self.helpers.dns`:

```python
# resolve a hostname
results = await self.helpers.resolve("example.com", rdtype="A")

# resolve with full record details
results = await self.helpers.resolve_full("example.com", rdtype="CNAME")
```

## cloudcheck (BLS)

[cloudcheck](https://github.com/blacklanternsecurity/cloudcheck) identifies which cloud provider (if any) owns a given IP or domain. It maintains a regularly-updated database of IP ranges for AWS, Azure, GCP, Cloudflare, and dozens of other providers. BBOT uses it to tag events with cloud provider info (e.g. `cloud-aws`, `cdn-cloudflare`).

Accessed via `self.helpers.cloudcheck`:

```python
result = await self.helpers.cloudcheck.lookup("1.2.3.4")
# CloudCheckResult with provider name, type (cdn, cloud, waf, etc.)
```

## radixtarget (BLS)

[radixtarget](https://github.com/blacklanternsecurity/radixtarget) is a high-performance radix tree for IP/DNS lookups. It is the data structure behind BBOT's target, seed, and blacklist storage, enabling fast scope checks against large target lists with CIDR and subdomain matching.

```python
from radixtarget import RadixTarget

rt = RadixTarget()
rt.insert("10.0.0.0/8")
rt.search("10.1.2.3")  # True
```

## asndb (BLS)

[asndb](https://github.com/blacklanternsecurity/asndb) provides ASN lookups for IP addresses, returning the owning organization, AS number, and subnet. BBOT uses it to enrich events with ASN metadata and to support ASN targets (e.g. `bbot -t AS1234`).

Accessed via `self.helpers.asn`:

```python
result = await self.helpers.asn.lookup("8.8.8.8")
# {"asn": 15169, "name": "GOOGLE", "description": "Google LLC", ...}
```

## Other Key Dependencies

| Library | What BBOT uses it for |
|---------|----------------------|
| [pydantic](https://docs.pydantic.dev/) | Preset/config validation, module config schemas (`BaseModuleConfig`) |
| [ansible-runner](https://ansible-runner.readthedocs.io/) | Module dependency installation (`deps_apt`, `deps_ansible`) |
| [yara-python](https://yara.readthedocs.io/) | Pattern matching in `excavate` (secret/credential extraction from HTTP responses) |
| [deepdiff](https://zepworks.com/deepdiff/) | HTTP response comparison for web modules (baseline diffing, wildcard detection) |
| [dnspython](https://dnspython.readthedocs.io/) | DNS record type constants and utilities (blastdns handles actual resolution) |
