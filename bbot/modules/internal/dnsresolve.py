import ipaddress
from contextlib import suppress
from cachetools import LRUCache

from bbot.errors import ValidationError
from bbot.core.helpers.dns.engine import all_rdtypes
from bbot.core.helpers.async_helpers import NamedLock
from bbot.modules.base import InterceptModule, BaseModule
from bbot.core.helpers.dns.helpers import extract_targets


class DNSResolve(InterceptModule):
    watched_events = ["*"]
    _priority = 1
    scope_distance_modifier = None

    class HostModule(BaseModule):
        _name = "host"
        _type = "internal"

        def _outgoing_dedup_hash(self, event):
            return hash((event, self.name, event.always_emit))

    @property
    def module_threads(self):
        return self.dns_config.get("threads", 25)

    async def setup(self):
        self.dns_config = self.scan.config.get("dns", {})
        self.dns_disable = self.dns_config.get("disable", False)
        if self.dns_disable:
            return None, "DNS resolution is disabled in the config"

        self.minimal = self.dns_config.get("minimal", False)
        self.dns_search_distance = max(0, int(self.dns_config.get("search_distance", 1)))
        self._emit_raw_records = None

        # event resolution cache
        self._event_cache = LRUCache(maxsize=10000)
        self._event_cache_locks = NamedLock()

        self.host_module = self.HostModule(self.scan)

        return True

    @property
    def _dns_search_distance(self):
        return max(self.scan.scope_search_distance, self.dns_search_distance)

    @property
    def emit_raw_records(self):
        if self._emit_raw_records is None:
            watching_raw_records = any(
                ["RAW_DNS_RECORD" in m.get_watched_events() for m in self.scan.modules.values()]
            )
            omitted_event_types = self.scan.config.get("omit_event_types", [])
            omit_raw_records = "RAW_DNS_RECORD" in omitted_event_types
            self._emit_raw_records = watching_raw_records or not omit_raw_records
        return self._emit_raw_records

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, **kwargs):
        dns_tags = set()
        raw_record_events = []
        event_whitelisted = False
        event_blacklisted = False

        event_is_ip = self.helpers.is_ip(event.host)

        event_host = str(event.host)
        event_host_hash = hash(event_host)

        # we do DNS resolution inside a lock to make sure we don't duplicate work
        # once the resolution happens, its results will be cached so it doesn't need to happen again
        async with self._event_cache_locks.lock(event_host_hash):
            try:
                # try to get from cache
                # the "main host event" is the original parent IP_ADDRESS or DNS_NAME
                main_host_event, dns_tags, event_whitelisted, event_blacklisted = self._event_cache[event_host_hash]
                # dns_tags, dns_children, event_whitelisted, event_blacklisted = self._event_cache[event_host_hash]
            except KeyError:

                main_host_event = self.get_dns_parent(event)

                rdtypes_to_resolve = ()
                if event_is_ip:
                    if not self.minimal:
                        rdtypes_to_resolve = ("PTR",)
                else:
                    if self.minimal:
                        rdtypes_to_resolve = ("A", "AAAA", "CNAME")
                    else:
                        rdtypes_to_resolve = all_rdtypes

                # first, we do DNS resolution
                queries = [(event_host, rdtype) for rdtype in rdtypes_to_resolve]
                error_rdtypes = []
                async for (query, rdtype), (answer, errors) in self.helpers.dns.resolve_raw_batch(queries):
                    if self.emit_raw_records and rdtype not in ("A", "AAAA", "CNAME", "PTR"):
                        raw_record_event = self.make_event(
                            {"host": str(event_host), "type": rdtype, "answer": answer.to_text()},
                            "RAW_DNS_RECORD",
                            parent=main_host_event,
                            tags=[f"{rdtype.lower()}-record"],
                            context=f"{rdtype} lookup on {{event.parent.host}} produced {{event.type}}",
                        )
                        raw_record_events.append(raw_record_event)
                    if errors:
                        error_rdtypes.append(rdtype)
                    for _rdtype, host in extract_targets(answer):
                        dns_tags.add(f"{rdtype.lower()}-record")
                        try:
                            main_host_event.dns_children[_rdtype].add(host)
                        except KeyError:
                            main_host_event.dns_children[_rdtype] = {host}

                # if there were dns resolution errors, notify the user with tags
                for rdtype in error_rdtypes:
                    if rdtype not in main_host_event.dns_children:
                        dns_tags.add(f"{rdtype.lower()}-error")

                # if there weren't any DNS children and it's not an IP address, tag as unresolved
                if not main_host_event.dns_children and not event_is_ip:
                    dns_tags.add("unresolved")

                # check DNS children against whitelists and blacklists
                for rdtype, children in main_host_event.dns_children.items():
                    if event_blacklisted:
                        break
                    for host in children:
                        # whitelisting / blacklisting based on resolved hosts
                        if rdtype in ("A", "AAAA", "CNAME"):
                            # having a CNAME to an in-scope resource doesn't make you in-scope
                            if (not event_whitelisted) and rdtype != "CNAME":
                                with suppress(ValidationError):
                                    if self.scan.whitelisted(host):
                                        event_whitelisted = True
                                        dns_tags.add(f"dns-whitelisted-{rdtype.lower()}")
                            # CNAME to a blacklisted resource, means you're blacklisted
                            with suppress(ValidationError):
                                if self.scan.blacklisted(host):
                                    dns_tags.add("blacklisted")
                                    dns_tags.add(f"dns-blacklisted-{rdtype.lower()}")
                                    event_blacklisted = True
                                    event_whitelisted = False
                                    break

                        # check for private IPs
                        try:
                            ip = ipaddress.ip_address(host)
                            if ip.is_private:
                                dns_tags.add("private-ip")
                        except ValueError:
                            continue

                # add DNS tags to main host
                for tag in dns_tags:
                    main_host_event.add_tag(tag)

                # set resolved_hosts attribute
                for rdtype, children in main_host_event.dns_children.items():
                    if rdtype in ("A", "AAAA", "CNAME"):
                        for host in children:
                            main_host_event._resolved_hosts.add(host)

                # store results in cache
                self._event_cache[event_host_hash] = main_host_event, dns_tags, event_whitelisted, event_blacklisted

        # abort if the event resolves to something blacklisted
        if event_blacklisted:
            return False, f"it has a blacklisted DNS record"

        # if the event resolves to an in-scope IP, set its scope distance to 0
        if event_whitelisted:
            self.debug(
                f"Making {main_host_event} in-scope because it resolves to an in-scope resource (A/AAAA)"
            )
            main_host_event.scope_distance = 0
            if event != main_host_event:
                self.debug(f"Making {event} in-scope because it resolves to an in-scope resource (A/AAAA)")
                event.scope_distance = 0

        # if the event is within our scan's search distance, handle wildcard
        if event.scope_distance <= self.scan.scope_search_distance:
            rdtypes_to_check = list(main_host_event.dns_children)
            self.hugeinfo(f"Checking {rdtypes_to_check}")
            await self.handle_wildcard_event(main_host_event)

        # emit the main host and its raw records
        if event != main_host_event:
            await self.emit_event(main_host_event)
        for raw_record_event in raw_record_events:
            await self.emit_event(raw_record_event)

        # kill runaway DNS chains
        dns_resolve_distance = getattr(event, "dns_resolve_distance", 0)
        if dns_resolve_distance >= self.helpers.dns.runaway_limit:
            self.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.helpers.dns.runaway_limit})"
            )
            main_host_event.dns_children = {}

        # emit DNS children
        if not self.minimal:
            in_dns_scope = -1 < event.scope_distance < self._dns_search_distance
            for rdtype, records in main_host_event.dns_children.items():
                module = self.scan._make_dummy_module_dns(rdtype)
                for record in records:
                    try:
                        child_event = self.scan.make_event(
                            record, "DNS_NAME", module=module, parent=main_host_event
                        )
                        child_event.discovery_context = f"{rdtype} record for {event.host} contains {child_event.type}: {child_event.host}"
                        # if it's a hostname and it's only one hop away, mark it as affiliate
                        if child_event.type == "DNS_NAME" and child_event.scope_distance == 1:
                            child_event.add_tag("affiliate")
                        if in_dns_scope or self.preset.in_scope(child_event):
                            self.debug(f"Queueing DNS child for {event}: {child_event}")
                            await self.emit_event(child_event)
                    except ValidationError as e:
                        self.warning(
                            f'Event validation failed for DNS child of {main_host_event}: "{record}" ({rdtype}): {e}'
                        )


        # transfer resolved hosts
        event._resolved_hosts = main_host_event._resolved_hosts

        # If the event is unresolved, change its type to DNS_NAME_UNRESOLVED
        if event.type == "DNS_NAME" and "unresolved" in event.tags:
            event.type = "DNS_NAME_UNRESOLVED"

    async def handle_wildcard_event(self, event):
        self.debug(f"Entering handle_wildcard_event({event})")
        tags = set()
        rdtypes_to_check = list(event.dns_children)
        if not rdtypes_to_check:
            return False, "", tags
        self.hugeinfo(f'{event.host}: Checking rdtypes {rdtypes_to_check}')
        try:
            event_host = str(event.host)
            # check if the dns name itself is a wildcard entry
            wildcard_rdtypes = await self.helpers.is_wildcard(event_host, dns_children=event.dns_children, rdtype=rdtypes_to_check)
            for rdtype, (is_wildcard, wildcard_host) in wildcard_rdtypes.items():
                if is_wildcard == False:
                    continue
                elif is_wildcard == True:
                    tags.add("wildcard")
                    wildcard_tag = "wildcard"
                elif is_wildcard == None:
                    wildcard_tag = "error"

                tags.add(f"{rdtype.lower()}-{wildcard_tag}")

            # wildcard event modification (www.evilcorp.com --> _wildcard.evilcorp.com)
            if wildcard_rdtypes and not "target" in event.tags:
                # these are the rdtypes that have wildcards
                wildcard_rdtypes_set = set(wildcard_rdtypes)
                # consider the event a full wildcard if all its records are wildcards
                event_is_wildcard = False
                if wildcard_rdtypes_set:
                    event_is_wildcard = all(r[0] == True for r in wildcard_rdtypes.values())

                if event_is_wildcard:
                    if event.type in ("DNS_NAME",) and not "_wildcard" in event.data.split("."):
                        wildcard_parent = self.helpers.parent_domain(event_host)
                        for rdtype, (_is_wildcard, _parent_domain) in wildcard_rdtypes.items():
                            if _is_wildcard:
                                wildcard_parent = _parent_domain
                                break
                        wildcard_data = f"_wildcard.{wildcard_parent}"
                        if wildcard_data != event.data:
                            return event_is_wildcard, wildcard_data, tags
        finally:
            self.debug(f"Finished handle_wildcard_event({event})")
        return False, "", tags

    def get_dns_parent(self, event):
        """
        Get the first parent DNS_NAME / IP_ADDRESS of an event. If one isn't found, create it.
        """
        for parent in event.get_parents(include_self=True):
            if parent.host == event.host and parent.type in ("IP_ADDRESS", "DNS_NAME", "DNS_NAME_UNRESOLVED"):
                return parent
        tags = set()
        if "target" in event.tags:
            tags.add("target")
        return self.scan.make_event(
            event.host,
            "DNS_NAME",
            module=self.host_module,
            parent=event,
            context="{event.parent.type} has host {event.type}: {event.host}",
            tags=tags,
        )
