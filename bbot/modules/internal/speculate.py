from .base import BaseInternalModule
import ipaddress


class speculate(BaseInternalModule):
    """
    Bridge the gap between ranges and ips, or ips and open ports
    in situations where e.g. a port scanner isn't enabled
    """

    watched_events = ["IP_RANGE", "URL", "DNS_NAME", "IP_ADDRESS"]
    produced_events = ["DNS_HOST", "OPEN_TCP_PORT", "IP_ADDRESS"]
    max_threads = 5

    def setup(self):
        self.open_port_consumers = any(["OPEN_TCP_PORT" in m.watched_events for m in self.scan.modules.values()])
        self.portscanner_enabled = any(["portscan" in m.flags for m in self.scan.modules.values()])
        return True

    def handle_event(self, event):
        # generate individual IP addresses from IP range
        if event.type == "IP_RANGE":
            net = ipaddress.ip_network(event.data)
            for x in net:
                self.emit_event(x, "IP_ADDRESS", source=event, internal=True)

        # generate open ports from URLs
        if event.type == "URL":
            self.emit_event(event.host, "DNS_NAME", source=event, internal=True)
            self.emit_event(
                self.helpers.make_netloc(event.host, event.port), "OPEN_TCP_PORT", source=event, internal=True
            )

        # generate open ports from hosts
        if event.type in ["DNS_NAME", "IP_ADDRESS"]:
            if self.open_port_consumers and not self.portscanner_enabled:
                self.emit_event(self.helpers.make_netloc(event.data, 80), "OPEN_TCP_PORT", source=event, internal=True)
                self.emit_event(
                    self.helpers.make_netloc(event.data, 443), "OPEN_TCP_PORT", source=event, internal=True
                )

    def filter_event(self, event):
        # don't accept events from self
        if str(event.module) == "speculate":
            return False
        return True
