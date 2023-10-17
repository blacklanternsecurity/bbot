# DNS

These are helpers related to DNS resolution. They are used throughout BBOT and its modules for performing DNS lookups and detecting DNS wildcards, etc.

Note that these helpers can be invoked directly from `self.helpers`, e.g.:

```python
self.helpers.resolve("evilcorp.com")
```

::: bbot.core.helpers.dns.DNSHelper
    handler: python
    options:
      members:
        - resolve
        - resolve_batch
        - resolve_raw
        - is_wildcard
        - is_wildcard_domain
