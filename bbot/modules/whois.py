from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class whois(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DOMAIN_REGISTRATION"]
    flags = ["safe", "passive"]
    meta = {
        "description": "Query WHOIS for domain registration data, e.g. registrar and registrant organization",
        "created_date": "2026-10-01",
        "author": "@shart123456",
    }

    class Config(BaseModuleConfig):
        include_raw: bool = Field(False, description="Include the raw WHOIS response in the event data")
        timeout: int = Field(10, description="WHOIS query timeout in seconds")
        concurrency: int = Field(5, description="Maximum concurrent WHOIS queries")

    per_domain_only = True
    # registrations of affiliate domains are a shadow IT signal
    scope_distance_modifier = 1
    _module_threads = 5

    async def setup(self):
        self.include_raw = self.config.get("include_raw", False)
        self.helpers.whois.configure(
            timeout=self.config.get("timeout", 10),
            concurrency=self.config.get("concurrency", 5),
        )
        return True

    def registrable_domain(self, hostname):
        if self.helpers.is_ip(hostname):
            return None
        extracted = self.helpers.tldextract(hostname)
        if not extracted.suffix:
            return None
        return extracted.top_domain_under_public_suffix or None

    async def filter_event(self, event):
        if self.registrable_domain(event.host) is None:
            return False, "No registrable domain"
        return True

    async def handle_event(self, event):
        domain = self.registrable_domain(event.host)
        record = await self.helpers.whois.lookup(domain, include_raw=self.include_raw)
        if not record:
            return
        registration_event = self.make_event(record, "DOMAIN_REGISTRATION", parent=event)
        if registration_event:
            await self.emit_event(
                registration_event,
                context=f'{{module}} queried WHOIS for "{domain}" and found {{event.type}}: {{event.pretty_string}}',
            )
