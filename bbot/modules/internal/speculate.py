from .base import BaseInternalModule
import ipaddress


class speculate(BaseInternalModule):
    """
    Bridge the gap between ranges and ips, or ips and open ports
    in situations where e.g. a port scanner isn't enabled
    """

    watched_events = ["IP_RANGE", "URL", "DNS_NAME", "IP_ADDRESS"]
    produced_events = ["DNS_HOST", "OPEN_TCP_PORT", "IP_ADDRESS"]
    options = {"max_hosts": 65536}
    options_desc = {"max_hosts": "Max number of IP_RANGE hosts to convert into IP_ADDRESS events"}
    max_threads = 5

    def setup(self):
        self.open_port_consumers = any(["OPEN_TCP_PORT" in m.watched_events for m in self.scan.modules.values()])
        self.portscanner_enabled = any(["portscan" in m.flags for m in self.scan.modules.values()])
        self.range_to_ip = True
        target_len = len(self.scan.target)
        if target_len > self.config.get("max_hosts", 65536):
            if not self.portscanner_enabled:
                self.warning(
                    f"Selected target ({target_len:,} hosts) is too large, skipping IP_RANGE --> IP_ADDRESS speculation"
                )
                self.warning(f"Enabling a port scanner module is highly recommended")
            self.range_to_ip = False
        return True

    def handle_event(self, event):
        # generate individual IP addresses from IP range
        if event.type == "IP_RANGE" and self.range_to_ip:
            net = ipaddress.ip_network(event.data)
            for x in net:
                self.emit_event(x, "IP_ADDRESS", source=event, internal=True)

        # generate open ports, DNS_NAMES, and IPs from URLs
        if event.type == "URL":
            if event.host:
                self.emit_event(event.host, "DNS_NAME", source=event, internal=True)
                if event.port:
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
        # don't accept IP_RANGE --> IP_ADDRESS events from self
        if str(event.module) == "speculate":
            if not (event.type == "IP_ADDRESS" and str(getattr(event.source, "type")) == "IP_RANGE"):
                return False
        # don't act on weird DNS_NAMES
        if event.type == "DNS_NAME":
            if not any([x in event.tags for x in ("a_record", "aaaa_record")]):
                return False
        return True
