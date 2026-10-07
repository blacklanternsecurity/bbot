from bbot.modules.base import BaseInterceptModule
from bbot.core.config.models import BaseModuleConfig, Field


class whois(BaseInterceptModule):
    watched_events = ["DNS_NAME"]
    meta = {
        "description": "Enrich DNS_NAMEs with WHOIS registration data, e.g. registrar and registrant organization",
        "created_date": "2026-10-07",
        "author": "@shart123456",
    }

    class Config(BaseModuleConfig):
        timeout: int = Field(10, description="WHOIS query timeout in seconds")

    # a WHOIS query is a blocking port-43 round trip that holds up the intercept chain behind it.
    # one per registrable domain, in-scope only, keeps that bounded by the scan's root domains.
    in_scope_only = True
    _priority = 4

    async def handle_event(self, event, **kwargs):
        domain = self.helpers.tldextract(event.host).top_domain_under_public_suffix
        # empty for IPs, bare public suffixes like "co.uk", and made-up TLDs like "host.local"
        if not domain:
            return
        record = await self.helpers.whois.lookup(domain, timeout=self.config["timeout"])
        if record:
            event.host_metadata.setdefault(domain, {})["whois"] = record

    async def cleanup(self):
        # when baddns is installed the cache is its process-global one, so it outlives the scan
        self.helpers.whois.clear_cache()
