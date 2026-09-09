import re
from collections import defaultdict

from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


PER_PARENT_CAP = 300
PTR_NOISE_PATTERNS = [
    # leading dotted IPv4-style octets, e.g. 001.106.103.218.static.netvigator.com
    re.compile(r"^\d{1,3}(\.\d{1,3}){3}(\.|$)"),
    # leading hyphenated IPv4-style octets, e.g. 000-1-246-220.static.netvigator.com
    re.compile(r"^\d{1,3}(-\d{1,3}){3}(\.|$|-)"),
]


def _collapse(subdomains, domain, query):
    """Filter PTR-style noise and collapse floods of sibling subdomains.

    When chaos returns more than PER_PARENT_CAP subdomains sharing a single
    immediate parent, drop the children and emit just the parent. Bbot's own
    DNS resolver will then determine wildcard status through normal sampling
    rather than us asserting it from chaos's evidence alone.
    """
    prefixes = []
    for s in subdomains:
        s = str(s).lower().strip(".*")
        if not s:
            continue
        if any(p.match(s) for p in PTR_NOISE_PATTERNS):
            continue
        prefixes.append(s)

    suffix = f".{query}"
    fqdns = []
    for p in prefixes:
        full = f"{p}.{domain}"
        if full.endswith(suffix):
            fqdns.append(full)

    parent_children = defaultdict(set)
    for name in fqdns:
        _, parent = name.split(".", 1)
        parent_children[parent].add(name)

    out = set()
    capped = []
    for parent, kids in parent_children.items():
        if len(kids) > PER_PARENT_CAP and parent != query:
            capped.append((parent, len(kids)))
            out.add(parent)
        else:
            out.update(kids)
    return out, capped


class chaos(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query ProjectDiscovery's Chaos API for subdomains",
        "created_date": "2022-08-14",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Chaos API key", sensitive=True, mandatory=True)

    base_url = "https://dns.projectdiscovery.io/dns"
    ping_url = f"{base_url}/example.com"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        _, domain = self.helpers.split_domain(query)
        url = f"{self.base_url}/{domain}/subdomains"
        return await self.api_request(url)

    async def parse_results(self, r, query):
        j = r.json()
        if not isinstance(j, dict):
            return set()
        domain = j.get("domain", "")
        if not domain:
            return set()
        subdomains = j.get("subdomains") or []
        if not subdomains:
            return set()
        results, capped = await self.helpers.run_in_executor_cpu(_collapse, subdomains, domain, query)
        for parent, n in capped:
            self.verbose(
                f"chaos returned {n:,} children of {parent}, "
                f"above per-parent cap of {PER_PARENT_CAP}; "
                f"emitting parent only and dropping children"
            )
        return results
