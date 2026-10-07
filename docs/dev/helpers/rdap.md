# RDAP

These are helpers for looking up domain registration data via [RDAP](https://about.rdap.org/), the successor to WHOIS.

`RDAPHelper` is accessible via `self.helpers.rdap`. It finds the right RDAP server using the IANA bootstrap, optionally follows the registry's link to the registrar's RDAP server, and enforces rate limits and a circuit breaker separately for each RDAP server. A failed lookup returns `None`. It never raises an exception.

```python
record = await self.helpers.rdap.lookup("evilcorp.com")
if record:
    self.hugesuccess(f"{record['domain']} is registered through {record['registrar']}")
```

A lookup never waits longer than `max_retry_after` for a server. If a server asks for a longer cooldown (HTTP 429 with a large `Retry-After`), lookups against it return `None` right away until the cooldown is over. Being rate limited doesn't count toward the circuit breaker. After `failure_threshold` consecutive failures, a server is skipped for `circuit_reset_seconds`. After that, one request is let through, and one more failure trips the breaker again. Settings can be changed with `self.helpers.rdap.configure(...)`.

The parsing functions (`normalize_rdap`, `parse_registrant`, `bootstrap_match`, etc.) are plain module-level functions, so they can be used on RDAP JSON without a scan.

::: bbot.core.helpers.rdap
    options:
      show_root_heading: false
