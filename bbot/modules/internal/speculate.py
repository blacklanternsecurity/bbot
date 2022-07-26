import ipaddress

from bbot.modules.internal.base import BaseInternalModule


class speculate(BaseInternalModule):
    """
    Bridge the gap between ranges and ips, or ips and open ports
    in situations where e.g. a port scanner isn't enabled
    """

    watched_events = ["IP_RANGE", "URL", "URL_UNVERIFIED", "DNS_NAME", "IP_ADDRESS", "HTTP_RESPONSE"]
    produced_events = ["DNS_NAME", "OPEN_TCP_PORT", "IP_ADDRESS"]
    options = {"max_hosts": 65536}
    options_desc = {"max_hosts": "Max number of IP_RANGE hosts to convert into IP_ADDRESS events"}
    max_event_handlers = 5
    scope_distance_modifier = 0
    _scope_shepherding = False

    def setup(self):
        self.open_port_consumers = any(["OPEN_TCP_PORT" in m.watched_events for m in self.scan.modules.values()])
        self.portscanner_enabled = any(["portscan " in m.flags for m in self.scan.modules.values()])
        self.range_to_ip = True
        target_len = len(self.scan.target)
        if target_len > self.config.get("max_hosts", 65536):
            if not self.portscanner_enabled:
                self.hugewarning(
                    f"Selected target ({target_len:,} hosts) is too large, skipping IP_RANGE --> IP_ADDRESS speculation"
                )
                self.hugewarning(f"Enabling a port scanner module is highly recommended")
            self.range_to_ip = False
        return True

    def handle_event(self, event):
        # generate individual IP addresses from IP range
        if event.type == "IP_RANGE" and self.range_to_ip:
            net = ipaddress.ip_network(event.data)
            for x in net:
                self.speculate_event(x, "IP_ADDRESS", source=event, internal=True)

        # parent domains
        if event.type == "DNS_NAME":
            parent = self.helpers.parent_domain(event.data)
            if parent != event.data:
                self.emit_event(parent, "DNS_NAME", source=event, internal=True)

        # generate open ports
        emit_open_ports = self.open_port_consumers and not self.portscanner_enabled
        # from URLs
        if event.type == "URL" or (event.type == "URL_UNVERIFIED" and emit_open_ports):
            if event.host and event.port not in (80, 443):
                self.speculate_event(
                    self.helpers.make_netloc(event.host, event.port), "OPEN_TCP_PORT", source=event, internal=True
                )
        # from hosts
        if emit_open_ports:
            # don't act on unresolved DNS_NAMEs
            if event.type == "IP_ADDRESS" or (
                event.type == "DNS_NAME" and any([x in event.tags for x in ("a_record", "aaaa_record")])
            ):
                self.speculate_event(
                    self.helpers.make_netloc(event.data, 80), "OPEN_TCP_PORT", source=event, internal=True
                )
                self.speculate_event(
                    self.helpers.make_netloc(event.data, 443), "OPEN_TCP_PORT", source=event, internal=True
                )

    def speculate_event(self, *args, **kwargs):
        """
        Wrapper around self.emit_event that sets the scope distance
        of an event to that of its parent
        """
        event = self.make_event(*args, **kwargs)
        if event:
            event.scope_distance = event.source.scope_distance
            self.emit_event(event)

    def filter_event(self, event):
        # don't accept IP_RANGE --> IP_ADDRESS events from self
        if str(event.module) == "speculate":
            if not (event.type == "IP_ADDRESS" and str(getattr(event.source, "type")) == "IP_RANGE"):
                return False
        if "dns-timeout" in event.tags:
            return False
        return True
