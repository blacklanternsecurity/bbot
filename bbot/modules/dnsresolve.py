from .base import BaseModule

class dnsresolve(BaseModule):

    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["IP_ADDRESS", "DNS_NAME"]
    max_threads = 25

    def handle_event(self, event):

        self.debug(f"trying to resolve {event.data}")
        r_set = self.helpers.resolve(str(event.data))
        for r in r_set:
            self.emit_event(r, source=event)
