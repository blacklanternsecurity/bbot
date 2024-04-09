import ipaddress
from contextlib import suppress
from cachetools import LRUCache

from bbot.errors import ValidationError
from bbot.modules.base import HookModule
from bbot.core.helpers.dns.engine import all_rdtypes
from bbot.core.helpers.async_helpers import NamedLock


class dnsresolve(HookModule):
    watched_events = ["*"]
    _priority = 1
    _max_event_handlers = 25

    async def setup(self):
        self.dns_resolution = self.scan.config.get("dns_resolution", False)
        self.scope_search_distance = max(0, int(self.scan.config.get("scope_search_distance", 0)))
        self.scope_dns_search_distance = max(0, int(self.scan.config.get("scope_dns_search_distance", 1)))
        # event resolution cache
        self._event_cache = LRUCache(maxsize=10000)
        self._event_cache_locks = NamedLock()
        return True

    @property
    def scope_distance_modifier(self):
        return max(self.scope_search_distance, self.scope_dns_search_distance)

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event):
        dns_tags = set()
        dns_children = dict()

        # DNS resolution
        event_whitelisted = False
        event_blacklisted = False

        event_host = str(event.host)
        event_host_hash = hash(str(event.host))
        event_is_ip = self.helpers.is_ip(event.host)

        emit_children = event_host_hash not in self._event_cache

        async with self._event_cache_locks.lock(event_host_hash):
            try:
                # try to get from cache
                dns_tags, dns_children, event_whitelisted, event_blacklisted = self._event_cache[event_host_hash]
            except KeyError:
                queries = [(event_host, rdtype) for rdtype in all_rdtypes]
                error_rdtypes = []
                async for (query, rdtype), (answers, errors) in self.helpers.dns.resolve_raw_batch(queries):
                    if errors:
                        error_rdtypes.append(rdtype)
                    for answer, _rdtype in answers:
                        dns_tags.add(f"{rdtype.lower()}-record")
                        try:
                            dns_children[_rdtype].add(answer)
                        except KeyError:
                            dns_children[_rdtype] = {answer}

                for rdtype in error_rdtypes:
                    if rdtype not in dns_children:
                        dns_tags.add(f"{rdtype.lower()}-error")

                if not event_is_ip:
                    if dns_children:
                        dns_tags.add("resolved")
                    else:
                        dns_tags.add("unresolved")

                for rdtype, children in dns_children.items():
                    if event_blacklisted:
                        break
                    for host in children:
                        # whitelisting / blacklisting based on resolved hosts
                        if rdtype in ("A", "AAAA", "CNAME"):
                            event.resolved_hosts.add(host)
                            # having a CNAME to an in-scope resource doesn't make you in-scope
                            if not event_whitelisted and rdtype != "CNAME":
                                with suppress(ValidationError):
                                    if self.scan.whitelisted(host):
                                        event_whitelisted = True
                            # CNAME to a blacklisted resources, means you're blacklisted
                            with suppress(ValidationError):
                                if self.scan.blacklisted(host):
                                    event_blacklisted = True
                                    break

                        # check for private IPs
                        try:
                            ip = ipaddress.ip_address(host)
                            if ip.is_private:
                                dns_tags.add("private-ip")
                        except ValueError:
                            continue

                self._event_cache[event_host_hash] = dns_tags, dns_children, event_whitelisted, event_blacklisted

        # kill runaway DNS chains
        dns_resolve_distance = getattr(event, "dns_resolve_distance", 0)
        if dns_resolve_distance >= self.helpers.dns.max_dns_resolve_distance:
            self.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.helpers.dns.max_dns_resolve_distance})"
            )
            dns_children = {}

        if event.type in ("DNS_NAME", "IP_ADDRESS"):
            event.dns_children = dns_children
            for tag in dns_tags:
                event.add_tag(tag)

        if event_blacklisted:
            event.add_tag("blacklisted")
            reason = "event host"
            if event_blacklisted:
                reason = "DNS associations"
            self.debug(f"Omitting due to blacklisted {reason}: {event}")

        if event_whitelisted:
            self.debug(f"Making {event} in-scope because it resolves to an in-scope resource")
            event.scope_distance = 0

        # DNS_NAME --> DNS_NAME_UNRESOLVED
        if event.type == "DNS_NAME" and "unresolved" in event.tags and not "target" in event.tags:
            event.type = "DNS_NAME_UNRESOLVED"

        # check for wildcards
        if event.scope_distance <= self.scan.scope_search_distance:
            if not "unresolved" in event.tags:
                if not self.helpers.is_ip_type(event.host):
                    await self.helpers.dns.handle_wildcard_event(event)

        # speculate DNS_NAMES and IP_ADDRESSes from other event types
        source_event = event
        if (
            event.host
            and event.type not in ("DNS_NAME", "DNS_NAME_UNRESOLVED", "IP_ADDRESS", "IP_RANGE")
            and not (event.type in ("OPEN_TCP_PORT", "URL_UNVERIFIED") and str(event.module) == "speculate")
        ):
            source_event = self.make_event(event.host, "DNS_NAME", source=event)
            # only emit the event if it's not already in the parent chain
            if source_event is not None and source_event not in event.get_sources():
                source_event.scope_distance = event.scope_distance
                if "target" in event.tags:
                    source_event.add_tag("target")
                self.scan.manager.queue_event(source_event)

        ### Emit DNS children ###
        if emit_children:
            in_dns_scope = -1 < event.scope_distance < self.scope_distance_modifier
            dns_child_events = []
            if event.dns_children:
                for rdtype, records in event.dns_children.items():
                    module = self.scan._make_dummy_module_dns(rdtype)
                    module._priority = 4
                    for record in records:
                        try:
                            child_event = self.scan.make_event(record, "DNS_NAME", module=module, source=source_event)
                            # if it's a hostname and it's only one hop away, mark it as affiliate
                            if child_event.type == "DNS_NAME" and child_event.scope_distance == 1:
                                child_event.add_tag("affiliate")
                            host_hash = hash(str(child_event.host))
                            if in_dns_scope or self.preset.in_scope(child_event):
                                dns_child_events.append(child_event)
                        except ValidationError as e:
                            self.warning(
                                f'Event validation failed for DNS child of {source_event}: "{record}" ({rdtype}): {e}'
                            )
            for child_event in dns_child_events:
                self.debug(f"Queueing DNS child for {event}: {child_event}")
                self.scan.manager.queue_event(child_event)
