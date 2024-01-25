import dns.zone
import dns.query

from bbot.modules.base import BaseModule


class dnszonetransfer(BaseModule):
    flags = ["subdomain-enum", "active", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Attempt DNS zone transfers"}
    options = {"timeout": 10}
    options_desc = {"timeout": "Max seconds to wait before timing out"}
    _max_event_handlers = 5
    suppress_dupes = False

    async def setup(self):
        self.timeout = self.config.get("timeout", 10)
        return True

    async def filter_event(self, event):
        if any([x in event.tags for x in ("ns-record", "soa-record")]):
            return True
        return False

    async def handle_event(self, event):
        domain = event.data
        self.debug("Finding nameservers with NS/SOA query")
        nameservers = list(await self.helpers.resolve(event.data, type=("NS", "SOA")))
        nameserver_ips = set()
        for n in nameservers:
            nameserver_ips.update(await self.helpers.resolve(n))
        self.debug(f"Found {len(nameservers):} nameservers for domain {domain}")
        for nameserver in nameserver_ips:
            if self.scan.stopping:
                break
            try:
                self.debug(f"Attempting zone transfer against {nameserver} for domain {domain}")
                zone = await self.scan.run_in_executor(self.zone_transfer, nameserver, domain)
            except Exception as e:
                self.debug(f"Error retrieving zone for {domain}: {e}")
                continue
            self.hugesuccess(f"Successful zone transfer against {nameserver} for domain {domain}!")
            finding_description = f"Successful DNS zone transfer against {nameserver} for {domain}"
            await self.emit_event(
                {"host": str(event.host), "description": finding_description}, "FINDING", source=event
            )
            for name, ttl, rdata in zone.iterate_rdatas():
                if str(name) == "@":
                    parent_data = domain
                else:
                    parent_data = f"{name}.{domain}"
                parent_event = self.make_event(parent_data, "DNS_NAME", event)
                if not parent_event or parent_event == event:
                    parent_event = event
                else:
                    await self.emit_event(parent_event)
                for rdtype, t in self.helpers.dns.extract_targets(rdata):
                    if not self.helpers.is_ip(t):
                        t = f"{t}.{domain}"
                    module = self.helpers.dns._get_dummy_module(rdtype)
                    child_event = self.scan.make_event(t, "DNS_NAME", parent_event, module=module)
                    await self.emit_event(child_event)
            else:
                self.debug(f"No data returned by {nameserver} for domain {domain}")

    def zone_transfer(self, nameserver, domain):
        xfr_answer = dns.query.xfr(nameserver, domain, timeout=self.timeout, lifetime=self.timeout)
        zone = dns.zone.from_xfr(xfr_answer)
        return zone
