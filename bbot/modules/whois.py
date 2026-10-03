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

    per_domain_only = True
    # registrations of affiliate domains are a shadow IT signal
    scope_distance_modifier = 1

    def registrable_domain(self, hostname):
        if self.helpers.is_ip(hostname):
            return None
        return self.helpers.tldextract(hostname).top_domain_under_public_suffix or None

    async def filter_event(self, event):
        if self.registrable_domain(event.host) is None:
            return False, "No registrable domain"
        return True

    async def handle_event(self, event):
        domain = self.registrable_domain(event.host)
        record = await self.helpers.whois.lookup(
            domain, include_raw=self.config["include_raw"], timeout=self.config["timeout"]
        )
        if not record:
            return
        registration_event = self.make_event(record, "DOMAIN_REGISTRATION", parent=event)
        if registration_event:
            await self.emit_event(
                registration_event,
                context=f'{{module}} queried WHOIS for "{domain}" and found {{event.type}}: {{event.pretty_string}}',
            )
