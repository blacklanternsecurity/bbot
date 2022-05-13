from .base import BaseModule


class dnsresolve(BaseModule):

    flags = ["subdomain-enum"]
    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["IP_ADDRESS", "DNS_NAME"]
    in_scope_only = False
    max_threads = 20

    def handle_event(self, event):
        self.debug(f"trying to resolve {event.data}")
        r_set = self.helpers.resolve(str(event.data))
        for r in r_set:
            if self.helpers.is_ip(r):
                event_type = "IP_ADDRESS"
            else:
                event_type = "DNS_NAME"
            self.emit_event(r, event_type, source=event)
