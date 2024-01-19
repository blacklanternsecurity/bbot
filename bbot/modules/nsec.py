from bbot.modules.base import BaseModule


class NSEC(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Enumerate subdomains by NSEC-walking"}
    _max_event_handlers = 5

    async def filter_event(self, event):
        if "ns-record" in event.tags:
            return True
        return False

    async def handle_event(self, event):
        emitted_finding = False
        async for result in self.nsec_walk(event.data):
            if not emitted_finding:
                emitted_finding = True
                await self.emit_event(
                    {"host": event.data, "description": f"DNSSEC NSEC Zone Walking Enabled for domain: {event.data}"},
                    "FINDING",
                    source=event,
                )
            await self.emit_event(result, "DNS_NAME", source=event)

    async def get_nsec_record(self, domain):
        domain = domain.replace("\\000.", "")
        try:
            for result in await self.helpers.resolve(domain, type="NSEC"):
                return str(result)
        except Exception as e:
            self.warning(f"Error getting NSEC record for {domain}: {e}")

    async def nsec_walk(self, domain):
        encountered = set()
        current_domain = domain
        while 1:
            next_domain = await self.get_nsec_record(current_domain)
            if next_domain is None or next_domain in encountered:
                break
            encountered.add(next_domain)
            if not next_domain.startswith("\\"):
                yield next_domain
            current_domain = next_domain
