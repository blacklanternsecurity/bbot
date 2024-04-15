import ipaddress
from contextlib import suppress
from cachetools import LRUCache

from bbot.errors import ValidationError
from bbot.modules.base import HookModule
from bbot.core.helpers.dns.engine import all_rdtypes
from bbot.core.helpers.async_helpers import NamedLock


class DNS(HookModule):
    watched_events = ["*"]
    _priority = 1
    _max_event_handlers = 25
    scope_distance_modifier = None

    async def setup(self):
        self.dns_resolution = True
        # you can disable DNS resolution with either the "dns" or "dns_resolution" config options
        for key in ("dns", "dns_resolution"):
            if self.scan.config.get(key, None) is False:
                self.dns_resolution = False
        self.scope_search_distance = max(0, int(self.scan.config.get("scope_search_distance", 0)))
        self.scope_dns_search_distance = max(0, int(self.scan.config.get("scope_dns_search_distance", 1)))

        # event resolution cache
        self._event_cache = LRUCache(maxsize=10000)
        self._event_cache_locks = NamedLock()

        return True

    @property
    def _dns_search_distance(self):
        return max(self.scope_search_distance, self.scope_dns_search_distance)

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, kwargs):
        dns_tags = set()
        dns_children = dict()
        event_whitelisted = False
        event_blacklisted = False

        event_host = str(event.host)
        event_host_hash = hash(str(event.host))
        event_is_ip = self.helpers.is_ip(event.host)

        # only emit DNS children if we haven't seen this host before
        emit_children = self.dns_resolution and event_host_hash not in self._event_cache

        # we do DNS resolution inside a lock to make sure we don't duplicate work
        # once the resolution happens, it will be cached so it doesn't need to happen again
        async with self._event_cache_locks.lock(event_host_hash):
            try:
                # try to get from cache
                dns_tags, dns_children, event_whitelisted, event_blacklisted = self._event_cache[event_host_hash]
            except KeyError:
                if event_is_ip:
                    rdtypes_to_resolve = ["PTR"]
                else:
                    rdtypes_to_resolve = all_rdtypes

                # if missing from cache, do DNS resolution
                queries = [(event_host, rdtype) for rdtype in rdtypes_to_resolve]
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

                if dns_children:
                    dns_tags.add("resolved")
                elif not event_is_ip:
                    dns_tags.add("unresolved")

                for rdtype, children in dns_children.items():
                    if event_blacklisted:
                        break
                    for host in children:
                        # whitelisting / blacklisting based on resolved hosts
                        if rdtype in ("A", "AAAA", "CNAME"):
                            # having a CNAME to an in-scope resource doesn't make you in-scope
                            if not event_whitelisted and rdtype != "CNAME":
                                with suppress(ValidationError):
                                    if self.scan.whitelisted(host):
                                        event_whitelisted = True
                            # CNAME to a blacklisted resources, means you're blacklisted
                            with suppress(ValidationError):
                                if self.scan.blacklisted(host):
                                    dns_tags.add("blacklisted")
                                    event_blacklisted = True
                                    break

                        # check for private IPs
                        try:
                            ip = ipaddress.ip_address(host)
                            if ip.is_private:
                                dns_tags.add("private-ip")
                        except ValueError:
                            continue

                # store results in cache
                self._event_cache[event_host_hash] = dns_tags, dns_children, event_whitelisted, event_blacklisted

        # abort if the event resolves to something blacklisted
        if event_blacklisted:
            event.add_tag("blacklisted")
            return False, f"it has a blacklisted DNS record"

        # set resolved_hosts attribute
        for rdtype, children in dns_children.items():
            if rdtype in ("A", "AAAA", "CNAME"):
                for host in children:
                    event.resolved_hosts.add(host)

        # set dns_children attribute
        event.dns_children = dns_children

        # if the event resolves to an in-scope IP, set its scope distance to 0
        if event_whitelisted:
            self.debug(f"Making {event} in-scope because it resolves to an in-scope resource")
            event.scope_distance = 0

        # check for wildcards, only if the event resolves to something isn't an IP
        if (not event_is_ip) and (dns_children):
            if event.scope_distance <= self.scan.scope_search_distance:
                await self.handle_wildcard_event(event)

        # kill runaway DNS chains
        dns_resolve_distance = getattr(event, "dns_resolve_distance", 0)
        if dns_resolve_distance >= self.helpers.dns.max_dns_resolve_distance:
            self.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.helpers.dns.max_dns_resolve_distance})"
            )
            dns_children = {}

        # if the event is a DNS_NAME or IP, tag with "a-record", "ptr-record", etc.
        if event.type in ("DNS_NAME", "IP_ADDRESS"):
            for tag in dns_tags:
                event.add_tag(tag)

        # If the event is unresolved, change its type to DNS_NAME_UNRESOLVED
        if event.type == "DNS_NAME" and "unresolved" in event.tags and not "target" in event.tags:
            event.type = "DNS_NAME_UNRESOLVED"

        # speculate DNS_NAMES and IP_ADDRESSes from other event types
        source_event = event
        if (
            event.host
            and event.type not in ("DNS_NAME", "DNS_NAME_UNRESOLVED", "IP_ADDRESS", "IP_RANGE")
            and not (event.type in ("OPEN_TCP_PORT", "URL_UNVERIFIED") and str(event.module) == "speculate")
        ):
            source_module = self.scan._make_dummy_module("host", _type="internal")
            source_event = self.scan.make_event(event.host, "DNS_NAME", module=source_module, source=event)
            # only emit the event if it's not already in the parent chain
            if source_event is not None and source_event not in event.get_sources():
                source_event.scope_distance = event.scope_distance
                if "target" in event.tags:
                    source_event.add_tag("target")
                await self.emit_event(source_event)

        # emit DNS children
        if emit_children:
            in_dns_scope = -1 < event.scope_distance < self._dns_search_distance
            dns_child_events = []
            if dns_children:
                for rdtype, records in dns_children.items():
                    module = self.scan._make_dummy_module_dns(rdtype)
                    module._priority = 4
                    for record in records:
                        try:
                            child_event = self.scan.make_event(record, "DNS_NAME", module=module, source=source_event)
                            # if it's a hostname and it's only one hop away, mark it as affiliate
                            if child_event.type == "DNS_NAME" and child_event.scope_distance == 1:
                                child_event.add_tag("affiliate")
                            if in_dns_scope or self.preset.in_scope(child_event):
                                dns_child_events.append(child_event)
                        except ValidationError as e:
                            self.warning(
                                f'Event validation failed for DNS child of {source_event}: "{record}" ({rdtype}): {e}'
                            )
            for child_event in dns_child_events:
                self.debug(f"Queueing DNS child for {event}: {child_event}")
                await self.emit_event(child_event)

    async def handle_wildcard_event(self, event):
        self.debug(f"Entering handle_wildcard_event({event}, children={event.dns_children})")
        try:
            event_host = str(event.host)
            # check if the dns name itself is a wildcard entry
            wildcard_rdtypes = await self.helpers.is_wildcard(event_host)
            for rdtype, (is_wildcard, wildcard_host) in wildcard_rdtypes.items():
                wildcard_tag = "error"
                if is_wildcard == True:
                    event.add_tag("wildcard")
                    wildcard_tag = "wildcard"
                event.add_tag(f"{rdtype.lower()}-{wildcard_tag}")

            # wildcard event modification (www.evilcorp.com --> _wildcard.evilcorp.com)
            if wildcard_rdtypes:
                # these are the rdtypes that successfully resolve
                resolved_rdtypes = set([c.upper() for c in event.dns_children])
                # these are the rdtypes that have wildcards
                wildcard_rdtypes_set = set(wildcard_rdtypes)
                # consider the event a full wildcard if all its records are wildcards
                event_is_wildcard = False
                if resolved_rdtypes:
                    event_is_wildcard = all(r in wildcard_rdtypes_set for r in resolved_rdtypes)

                if event_is_wildcard:
                    if event.type in ("DNS_NAME",) and not "_wildcard" in event.data.split("."):
                        wildcard_parent = self.helpers.parent_domain(event_host)
                        for rdtype, (_is_wildcard, _parent_domain) in wildcard_rdtypes.items():
                            if _is_wildcard:
                                wildcard_parent = _parent_domain
                                break
                        wildcard_data = f"_wildcard.{wildcard_parent}"
                        if wildcard_data != event.data:
                            self.debug(f'Wildcard detected, changing event.data "{event.data}" --> "{wildcard_data}"')
                            event.data = wildcard_data

        finally:
            self.debug(f"Finished handle_wildcard_event({event}, children={event.dns_children})")
