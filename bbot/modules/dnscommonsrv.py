from bbot.core.helpers.dns.helpers import common_srvs
from bbot.modules.templates.subdomain_enum import subdomain_enum


class dnscommonsrv(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "active", "safe"]
    meta = {"description": "Check for common SRV records", "created_date": "2022-05-15", "author": "@TheTechromancer"}
    dedup_strategy = "lowest_parent"
    deps_common = ["massdns"]

    options = {"max_depth": 2}
    options_desc = {"max_depth": "The maximum subdomain depth to brute-force SRV records"}

    async def setup(self):
        self.max_subdomain_depth = self.config.get("max_depth", 2)
        self.num_srvs = len(common_srvs)
        return True

    async def filter_event(self, event):
        subdomain_depth = self.helpers.subdomain_depth(event.host)
        if subdomain_depth > self.max_subdomain_depth:
            return False, f"its subdomain depth ({subdomain_depth}) exceeds max_depth={self.max_subdomain_depth}"
        return True

    async def handle_event(self, event):
        query = self.make_query(event)
        self.verbose(f'Brute-forcing {self.num_srvs:,} SRV records for "{query}"')
        for hostname in await self.helpers.dns.brute(self, query, common_srvs, type="SRV"):
            await self.emit_event(
                hostname,
                "DNS_NAME",
                parent=event,
                context=f'{{module}} tried {self.num_srvs:,} common SRV records against "{query}" and found {{event.type}}: {{event.data}}',
            )
