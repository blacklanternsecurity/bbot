import random
import ipaddress

from bbot.core.helpers.misc import parse_port_string
from bbot.modules.internal.base import BaseInternalModule


class speculate(BaseInternalModule):
    """
    Bridge the gap between ranges and ips, or ips and open ports
    in situations where e.g. a port scanner isn't enabled
    """

    watched_events = [
        "IP_RANGE",
        "URL",
        "URL_UNVERIFIED",
        "DNS_NAME",
        "DNS_NAME_UNRESOLVED",
        "IP_ADDRESS",
        "HTTP_RESPONSE",
        "STORAGE_BUCKET",
    ]
    produced_events = ["DNS_NAME", "OPEN_TCP_PORT", "IP_ADDRESS", "FINDING"]
    flags = ["passive"]
    meta = {"description": "Derive certain event types from others by common sense"}

    options = {"max_hosts": 65536, "ports": "80,443"}
    options_desc = {
        "max_hosts": "Max number of IP_RANGE hosts to convert into IP_ADDRESS events",
        "ports": "The set of ports to speculate on",
    }
    max_event_handlers = 5
    scope_distance_modifier = 1
    _scope_shepherding = False
    _priority = 4

    async def setup(self):
        self.open_port_consumers = any(["OPEN_TCP_PORT" in m.watched_events for m in self.scan.modules.values()])
        self.portscanner_enabled = any(["portscan" in m.flags for m in self.scan.modules.values()])
        self.range_to_ip = True
        self.dns_resolution = self.scan.config.get("dns_resolution", True)

        port_string = self.config.get("ports", "80,443")

        try:
            self.ports = parse_port_string(port_string)
        except ValueError as e:
            self.warning(f"Error parsing ports: {e}")
            return False

        if not self.portscanner_enabled:
            self.info(f"No portscanner enabled. Assuming open ports: {', '.join(str(x) for x in self.ports)}")

        target_len = len(self.scan.target)
        if target_len > self.config.get("max_hosts", 65536):
            if not self.portscanner_enabled:
                self.hugewarning(
                    f"Selected target ({target_len:,} hosts) is too large, skipping IP_RANGE --> IP_ADDRESS speculation"
                )
                self.hugewarning(f"Enabling a port scanner (naabu or masscan) module is highly recommended")
            self.range_to_ip = False

        return True

    async def handle_event(self, event):
        # generate individual IP addresses from IP range
        if event.type == "IP_RANGE" and self.range_to_ip:
            net = ipaddress.ip_network(event.data)
            ips = list(net)
            random.shuffle(ips)
            for ip in ips:
                self.emit_event(ip, "IP_ADDRESS", source=event, internal=True)

        # parent domains
        if event.type == "DNS_NAME":
            parent = self.helpers.parent_domain(event.data)
            if parent != event.data:
                self.emit_event(parent, "DNS_NAME", source=event, internal=True)

        # generate open ports
        emit_open_ports = self.open_port_consumers and not self.portscanner_enabled
        # from URLs
        if event.type == "URL" or (event.type == "URL_UNVERIFIED" and emit_open_ports):
            if event.host and event.port not in self.ports:
                self.emit_event(
                    self.helpers.make_netloc(event.host, event.port),
                    "OPEN_TCP_PORT",
                    source=event,
                    internal=True,
                    quick=(event.type == "URL"),
                )

        # generate sub-directory URLS from URLS
        if event.type == "URL":
            url_parents = self.helpers.url_parents(event.data)
            for up in url_parents:
                url_event = self.make_event(f"{up}/", "URL_UNVERIFIED", source=event)
                if url_event is not None:
                    # inherit web spider distance from parent (don't increment)
                    source_web_spider_distance = getattr(event, "web_spider_distance", 0)
                    url_event.web_spider_distance = source_web_spider_distance
                    self.emit_event(url_event)

        # from hosts
        if emit_open_ports:
            # don't act on unresolved DNS_NAMEs
            usable_dns = False
            if event.type == "DNS_NAME":
                if (not self.dns_resolution) or ("a-record" in event.tags or "aaaa-record" in event.tags):
                    usable_dns = True

            if event.type == "IP_ADDRESS" or usable_dns:
                for port in self.ports:
                    self.emit_event(
                        self.helpers.make_netloc(event.data, port),
                        "OPEN_TCP_PORT",
                        source=event,
                        internal=True,
                        quick=True,
                    )

        # storage buckets etc.
        self.helpers.cloud.speculate(event)

    async def filter_event(self, event):
        # don't accept IP_RANGE --> IP_ADDRESS events from self
        if str(event.module) == "speculate":
            if not (event.type == "IP_ADDRESS" and str(getattr(event.source, "type")) == "IP_RANGE"):
                return False
        # don't accept errored DNS_NAMEs
        if any(t in event.tags for t in ("unresolved", "a-error", "aaaa-error")):
            return False
        return True
