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
    meta = {
        "description": "Derive certain event types from others by common sense",
        "created_date": "2022-05-03",
        "author": "@liquidsec",
    }

    options = {"max_hosts": 65536, "ports": "80,443", "essential_only": False}
    options_desc = {
        "max_hosts": "Max number of IP_RANGE hosts to convert into IP_ADDRESS events",
        "ports": "The set of ports to speculate on",
        "essential_only": "Only enable essential speculate features (no extra discovery)",
    }
    scope_distance_modifier = 1
    _priority = 4

    default_discovery_context = "speculated {event.type}: {event.data}"

    async def setup(self):
        scan_modules = [m for m in self.scan.modules.values() if m._type == "scan"]
        self.open_port_consumers = any("OPEN_TCP_PORT" in m.watched_events for m in scan_modules)
        # only consider active portscanners (still speculate if only passive ones are enabled)
        self.portscanner_enabled = any(
            "portscan" in m.flags and "active" in m.flags for m in self.scan.modules.values()
        )
        self.emit_open_ports = self.open_port_consumers and not self.portscanner_enabled
        self.range_to_ip = True
        self.dns_disable = self.scan.config.get("dns", {}).get("disable", False)
        self.essential_only = self.config.get("essential_only", False)
        self.org_stubs_seen = set()

        port_string = self.config.get("ports", "80,443")
        try:
            self.ports = self.helpers.parse_port_string(str(port_string))
        except ValueError as e:
            return False, f"Error parsing ports: {e}"

        if not self.portscanner_enabled:
            self.info(f"No portscanner enabled. Assuming open ports: {', '.join(str(x) for x in self.ports)}")

        target_len = len(self.scan.target.seeds)
        if target_len > self.config.get("max_hosts", 65536):
            if not self.portscanner_enabled:
                self.hugewarning(
                    f"Selected target ({target_len:,} hosts) is too large, skipping IP_RANGE --> IP_ADDRESS speculation"
                )
                self.hugewarning('Enabling the "portscan" module is highly recommended')
            self.range_to_ip = False

        return True

    async def handle_event(self, event):
        ### BEGIN ESSENTIAL SPECULATION ###
        # These features are required for smooth operation of bbot
        # I.e. they are not "osinty" or intended to discover anything, they only compliment other modules

        # we speculate on distance-1 stuff too, because distance-1 open ports are needed by certain modules like sslcert
        event_in_scope_distance = event.scope_distance <= (self.scan.scope_search_distance + 1)
        speculate_open_ports = self.emit_open_ports and event_in_scope_distance

        # generate individual IP addresses from IP range
        if event.type == "IP_RANGE" and self.range_to_ip:
            net = ipaddress.ip_network(event.data)
            ips = list(net)
            random.shuffle(ips)
            for ip in ips:
                await self.emit_event(
                    ip,
                    "IP_ADDRESS",
                    parent=event,
                    internal=True,
                    context=f"speculate converted range into individual IP_ADDRESS: {ip}",
                )

        # IP_ADDRESS / DNS_NAME --> OPEN_TCP_PORT
        if speculate_open_ports:
            # don't act on unresolved DNS_NAMEs
            usable_dns = False
            if event.type == "DNS_NAME":
                if self.dns_disable or event.resolved_hosts:
                    usable_dns = True

            if event.type == "IP_ADDRESS" or usable_dns:
                for port in self.ports:
                    await self.emit_event(
                        self.helpers.make_netloc(event.data, port),
                        "OPEN_TCP_PORT",
                        parent=event,
                        internal=True,
                        context="speculated {event.type}: {event.data}",
                    )

        ### END ESSENTIAL SPECULATION ###
        if self.essential_only:
            return

        # parent domains
        if event.type.startswith("DNS_NAME"):
            parent = self.helpers.parent_domain(event.host_original)
            if parent != event.data:
                await self.emit_event(
                    parent, "DNS_NAME", parent=event, context="speculated parent {event.type}: {event.data}"
                )

        # URL --> OPEN_TCP_PORT
        event_is_url = event.type == "URL"
        if event_is_url or (event.type == "URL_UNVERIFIED" and self.open_port_consumers):
            # only speculate port from a URL if it wouldn't be speculated naturally from the host
            if event.host and (event.port not in self.ports or not speculate_open_ports):
                await self.emit_event(
                    self.helpers.make_netloc(event.host, event.port),
                    "OPEN_TCP_PORT",
                    parent=event,
                    internal=not event_is_url,  # if the URL is verified, the port is definitely open
                    context=f"speculated {{event.type}} from {event.type}: {{event.data}}",
                )

        # speculate sub-directory URLS from URLS
        if event.type == "URL":
            url_parents = self.helpers.url_parents(event.data)
            for up in url_parents:
                url_event = self.make_event(f"{up}/", "URL_UNVERIFIED", parent=event)
                if url_event is not None:
                    # inherit web spider distance from parent (don't increment)
                    parent_web_spider_distance = getattr(event, "web_spider_distance", 0)
                    url_event.web_spider_distance = parent_web_spider_distance
                    await self.emit_event(url_event, context="speculated web sub-directory {event.type}: {event.data}")

        # speculate URL_UNVERIFIED from URL or any event with "url" attribute
        event_is_url = event.type == "URL"
        event_has_url = isinstance(event.data, dict) and "url" in event.data
        event_tags = ["httpx-safe"] if event.type in ("CODE_REPOSITORY", "SOCIAL") else []
        if event_is_url or event_has_url:
            if event_is_url:
                url = event.data
            else:
                url = event.data["url"]
            # only emit the url if it's not already in the event's history
            if not any(e.type == "URL_UNVERIFIED" and e.data == url for e in event.get_parents()):
                await self.emit_event(
                    url,
                    "URL_UNVERIFIED",
                    tags=event_tags,
                    parent=event,
                    context="speculated {event.type}: {event.data}",
                )

        # ORG_STUB from TLD, SOCIAL, AZURE_TENANT
        org_stubs = set()
        if event.type == "DNS_NAME" and event.scope_distance == 0:
            tldextracted = self.helpers.tldextract(event.data)
            top_domain_under_public_suffix = getattr(tldextracted, "top_domain_under_public_suffix", "")
            if top_domain_under_public_suffix:
                tld_stub = getattr(tldextracted, "domain", "")
                if tld_stub:
                    decoded_tld_stub = self.helpers.smart_decode_punycode(tld_stub)
                    org_stubs.add(decoded_tld_stub)
                    org_stubs.add(self.helpers.unidecode(decoded_tld_stub))
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
                stub_event = self.make_event(stub, "ORG_STUB", parent=event)
                if stub_event:
                    await self.emit_event(stub_event, context="speculated {event.type}: {event.data}")

        # USERNAME --> EMAIL
        if event.type == "USERNAME":
            email = event.data.split(":", 1)[-1]
            if validators.soft_validate(email, "email"):
                email_event = self.make_event(email, "EMAIL_ADDRESS", parent=event, tags=["affiliate"])
                if email_event:
                    await self.emit_event(email_event, context="detected {event.type}: {event.data}")
