import dns.zone
import dns.query

from .base import BaseModule


class dnszonetransfer(BaseModule):

    flags = ["subdomain-enum", "active"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    max_threads = 5
    suppress_dupes = False
    in_scope_only = True

    def filter_event(self, event):
        if any([x in event.tags for x in ("ns_record", "soa_record")]):
            return True
        return False

    def handle_event(self, event):
        domain = event.data
        nameservers = list(self.helpers.resolve(event.data, type=("NS", "SOA")))
        nameserver_ips = set()
        for n in nameservers:
            nameserver_ips.update(self.helpers.resolve(n))
        self.debug(f"Found {len(nameservers):} nameservers for domain {domain}")
        for nameserver in nameserver_ips:
            xfr_answer = dns.query.xfr(nameserver, domain)
            self.debug(f"Attempting zone transfer against {nameserver} for domain {domain}")
            try:
                zone = dns.zone.from_xfr(xfr_answer)
            except Exception as e:
                self.debug(f"Error retrieving zone: {e}")
                continue
            self.hugesuccess(f"Successful zone transfer against {nameserver} for domain {domain}!")
            for name, ttl, rdata in zone.iterate_rdatas():
                if str(name) == "@":
                    parent_data = domain
                else:
                    parent_data = f"{name}.{domain}"
                parent_event = self.make_event(parent_data, "DNS_NAME", event)
                if not parent_event or parent_event == event:
                    parent_event = event
                else:
                    self.emit_event(parent_event)
                for rdtype, t in self.helpers.dns.extract_targets(rdata):
                    if not self.helpers.is_ip(t):
                        t = f"{t}.{domain}"
                    module = self.helpers.dns._get_dummy_module(rdtype)
                    child_event = self.scan.make_event(t, "DNS_NAME", parent_event, module=module)
                    self.emit_event(child_event)
            else:
                self.debug(f"No data returned by {nameserver} for domain {domain}")
