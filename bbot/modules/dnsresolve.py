from .base import BaseModule

from contextlib import suppress


class dnsresolve(BaseModule):

    flags = ["subdomain-enum"]
    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["IP_ADDRESS", "DNS_NAME"]
    max_threads = 20
    suppress_dupes = False

    def handle_event(self, event):
        self.debug(f"Trying to resolve {event.data}")
        all_results = dict(self.helpers.resolve(str(event.data), type="all"))
        for rdtype, results in all_results.items():
            if self.scan.stopping:
                break
            tags = []
            if rdtype not in ("A", "AAAA"):
                tags = [f"{rdtype.lower()}_record"]
            if rdtype in ("A", "AAAA", "NS", "CNAME"):
                for r in results:
                    self.emit_host_event(r, source=event, tags=tags)
            elif rdtype in ("SRV", "MX"):
                for r in results:
                    with suppress(IndexError):
                        self.emit_host_event(r.split()[-1], source=event, tags=tags)
            elif rdtype == "SOA":
                for r in results:
                    with suppress(IndexError):
                        mname, rname = r.split()[:2]
                        self.emit_host_event(mname, source=event, tags=tags)
                        self.emit_host_event(rname, source=event, tags=tags)

    def emit_host_event(self, r, source, tags=[]):
        r = r.rstrip(".")
        if r:
            if self.helpers.is_ip(r):
                event_type = "IP_ADDRESS"
            else:
                event_type = "DNS_NAME"
            self.emit_event(r, event_type, source=source, tags=tags)
