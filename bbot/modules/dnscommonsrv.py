from bbot.core.helpers.dns.helpers import common_srvs
from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class dnscommonsrv(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "active"]
    meta = {"description": "Check for common SRV records", "created_date": "2022-05-15", "author": "@TheTechromancer"}
    dedup_strategy = "lowest_parent"
    deps_common = ["massdns"]

    class Config(BaseModuleConfig):
        max_depth: int = Field(2, description="The maximum subdomain depth to brute-force SRV records")
        recursive_mutations: bool = Field(
            False,
            description="If True, brute-force SRV records on hosts discovered by dnsbrute_mutations. Default False skips them.",
        )

    async def setup(self):
        self.max_subdomain_depth = self.config.get("max_depth", 2)
        self.num_srvs = len(common_srvs)
        return True

    async def filter_event(self, event):
        if not self.config.get("recursive_mutations", True) and any(t.startswith("mutation-") for t in event.tags):
            return False, "event was discovered by dnsbrute_mutations and recursive_mutations is False"
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
                context=f'{{module}} tried {self.num_srvs:,} common SRV records against "{query}" and found {{event.type}}: {{event.pretty_string}}',
            )
