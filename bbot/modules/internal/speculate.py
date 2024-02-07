import random
import ipaddress

from bbot.core.helpers import validators
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
        "SOCIAL",
        "AZURE_TENANT",
        "USERNAME",
    ]
    produced_events = ["DNS_NAME", "OPEN_TCP_PORT", "IP_ADDRESS", "FINDING", "ORG_STUB"]
    flags = ["passive"]
    meta = {"description": "Derive certain event types from others by common sense"}

    options = {"max_hosts": 65536, "ports": "80,443"}
    options_desc = {
        "max_hosts": "Max number of IP_RANGE hosts to convert into IP_ADDRESS events",
        "ports": "The set of ports to speculate on",
    }
    scope_distance_modifier = 1
    _priority = 4

    async def setup(self):
        scan_modules = [m for m in self.scan.modules.values() if m._type == "scan"]
        self.open_port_consumers = any(["OPEN_TCP_PORT" in m.watched_events for m in scan_modules])
        # only consider active portscanners (still speculate if only passive ones are enabled)
        self.portscanner_enabled = any(
            ["portscan" in m.flags and "active" in m.flags for m in self.scan.modules.values()]
        )
        self.emit_open_ports = self.open_port_consumers and not self.portscanner_enabled
        self.range_to_ip = True
        self.dns_resolution = self.scan.config.get("dns_resolution", True)
        self.org_stubs_seen = set()

        port_string = self.config.get("ports", "80,443")
        try:
            self.ports = self.helpers.parse_port_string(str(port_string))
        except ValueError as e:
            return False, f"Error parsing ports: {e}"

        if not self.portscanner_enabled:
            self.info(f"No portscanner enabled. Assuming open ports: {', '.join(str(x) for x in self.ports)}")

        target_len = len(self.scan.target)
        if target_len > self.config.get("max_hosts", 65536):
            if not self.portscanner_enabled:
                self.hugewarning(
                    f"Selected target ({target_len:,} hosts) is too large, skipping IP_RANGE --> IP_ADDRESS speculation"
                )
                self.hugewarning(f"Enabling a port scanner (nmap or masscan) module is highly recommended")
            self.range_to_ip = False

        return True

    async def handle_event(self, event):
        # generate individual IP addresses from IP range
        if event.type == "IP_RANGE" and self.range_to_ip:
            net = ipaddress.ip_network(event.data)
            ips = list(net)
            random.shuffle(ips)
            for ip in ips:
                await self.emit_event(ip, "IP_ADDRESS", source=event, internal=True)

        # parent domains
        if event.type == "DNS_NAME":
            parent = self.helpers.parent_domain(event.data)
            if parent != event.data:
                await self.emit_event(parent, "DNS_NAME", source=event, internal=True)

        # generate open ports

        # we speculate on distance-1 stuff too, because distance-1 open ports are needed by certain modules like sslcert
        event_in_scope_distance = event.scope_distance <= (self.scan.scope_search_distance + 1)
        speculate_open_ports = self.emit_open_ports and event_in_scope_distance

        # from URLs
        if event.type == "URL" or (event.type == "URL_UNVERIFIED" and self.open_port_consumers):
            # only speculate port from a URL if it wouldn't be speculated naturally from the host
            if event.host and (event.port not in self.ports or not speculate_open_ports):
                await self.emit_event(
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
                    await self.emit_event(url_event)

        # from hosts
        if speculate_open_ports:
            # don't act on unresolved DNS_NAMEs
            usable_dns = False
            if event.type == "DNS_NAME":
                if (not self.dns_resolution) or ("a-record" in event.tags or "aaaa-record" in event.tags):
                    usable_dns = True

            if event.type == "IP_ADDRESS" or usable_dns:
                for port in self.ports:
                    await self.emit_event(
                        self.helpers.make_netloc(event.data, port),
                        "OPEN_TCP_PORT",
                        source=event,
                        internal=True,
                        quick=True,
                    )

        # storage buckets etc.
        self.helpers.cloud.speculate(event)

        # ORG_STUB from TLD, SOCIAL, AZURE_TENANT
        org_stubs = set()
        if event.type == "DNS_NAME" and event.scope_distance == 0:
            tldextracted = self.helpers.tldextract(event.data)
            registered_domain = getattr(tldextracted, "registered_domain", "")
            if registered_domain:
                tld_stub = getattr(tldextracted, "domain", "")
                if tld_stub:
                    org_stubs.add(tld_stub)
        elif event.type == "SOCIAL":
            stub = event.data.get("stub", "")
            if stub:
                org_stubs.add(stub.lower())
        elif event.type == "AZURE_TENANT":
            tenant_names = event.data.get("tenant-names", [])
            org_stubs.update(set(tenant_names))
        for stub in org_stubs:
            stub_hash = hash(stub)
            if stub_hash not in self.org_stubs_seen:
                self.org_stubs_seen.add(stub_hash)
                stub_event = self.make_event(stub, "ORG_STUB", source=event)
                if event.scope_distance > 0:
                    stub_event.scope_distance = event.scope_distance
                await self.emit_event(stub_event)

        # USERNAME --> EMAIL
        if event.type == "USERNAME":
            email = event.data.split(":", 1)[-1]
            if validators.soft_validate(email, "email"):
                email_event = self.make_event(email, "EMAIL_ADDRESS", source=event, tags=["affiliate"])
                email_event.scope_distance = event.scope_distance
                await self.emit_event(email_event)

    async def filter_event(self, event):
        # don't accept errored DNS_NAMEs
        if any(t in event.tags for t in ("unresolved", "a-error", "aaaa-error")):
            return False, "there were errors resolving this hostname"
        return True
