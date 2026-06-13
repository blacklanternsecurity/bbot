import sys
from contextlib import suppress

from blastdns import DNSResult

from bbot.errors import ValidationError
from bbot.core.helpers.misc import cached_ip_address
from bbot.core.helpers.dns.helpers import all_rdtypes, extract_targets, record_to_text
from bbot.modules.base import BaseInterceptModule, BaseModule


class DNSResolve(BaseInterceptModule):
    watched_events = ["*"]
    produced_events = ["DNS_NAME", "IP_ADDRESS", "IP_RANGE", "RAW_DNS_RECORD"]
    meta = {"description": "Perform DNS resolution", "created_date": "2022-04-08", "author": "@TheTechromancer"}
    _priority = 1
    scope_distance_modifier = None

    class HostModule(BaseModule):
        _name = "host"
        _type = "internal"

    @property
    def module_threads(self):
        return self.dns_config.get("threads", 25)

    async def setup(self):
        self.dns_config = self.scan.config.get("dns", {})
        self.dns_disable = self.dns_config.get("disable", False)
        if self.dns_disable:
            return None, "DNS resolution is disabled in the config"

        self.minimal = self.dns_config.get("minimal", False)
        self.minimal_rdtypes = ("A", "AAAA", "CNAME")
        if self.minimal:
            self.non_minimal_rdtypes = ()
        else:
            self.non_minimal_rdtypes = tuple([t for t in all_rdtypes if t not in self.minimal_rdtypes])
        self.dns_search_distance = max(0, int(self.dns_config.get("search_distance", 1)))
        self._emit_raw_records = None

        self.filter_ptrs = self.dns_config.get("filter_ptrs", True)

        self.host_module = self.HostModule(self.scan)
        self.children_emitted = set()
        self.in_scope_children = set()
        self.child_edges_emitted = set()
        self.children_emitted_raw = set()
        self.hosts_resolved = set()

        return True

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, **kwargs):
        event_is_ip = self.helpers.is_ip(event.host)
        if event_is_ip:
            minimal_rdtypes = ("PTR",)
            non_minimal_rdtypes = ()
        else:
            minimal_rdtypes = self.minimal_rdtypes
            non_minimal_rdtypes = self.non_minimal_rdtypes

        # first, we find or create the main DNS_NAME or IP_ADDRESS associated with this event
        main_host_event, in_target, blacklisted, new_event = self.get_dns_parent(event)
        original_tags = set(event.tags)

        # minimal resolution - first, we resolve A/AAAA records for scope purposes
        if new_event or event is main_host_event:
            await self.resolve_event(main_host_event, types=minimal_rdtypes)
            # are any of its IPs in target scope or blacklisted?
            in_target, blacklisted = self.check_scope(main_host_event)
            if in_target and main_host_event.scope_distance > 0:
                # when filter_ptrs is enabled, don't promote PTR-derived hostnames to in-scope
                # this prevents rDNS results from triggering subdomain enumeration against unrelated domains
                # (e.g. scanning 1.2.3.0/24 would otherwise enumerate every PTR parent like randomothercorp.com)
                if self.filter_ptrs and "ptr" in main_host_event.tags:
                    self.debug(f"Not making {main_host_event} in-scope: PTR-derived hostname (filter_ptrs=true)")
                else:
                    self.debug(
                        f"Making {main_host_event} in-scope because it resolves to an in-scope resource (A/AAAA)"
                    )
                    main_host_event.scope_distance = 0

        # abort if the event resolves to something blacklisted
        if blacklisted:
            return False, "it has a blacklisted DNS record"

        # DNS resolution for hosts that aren't IPs
        if not event_is_ip:
            # if the event is within our dns search distance, resolve the rest of our records
            if main_host_event.scope_distance < self._dns_search_distance:
                await self.resolve_event(main_host_event, types=non_minimal_rdtypes)
                # check for wildcards if the event is within the scan's search distance
                if new_event and main_host_event.scope_distance <= self.scan.scope_search_distance:
                    event_data_changed = await self.handle_wildcard_event(main_host_event)
                    if event_data_changed:
                        # since data has changed, we check again whether it's a duplicate
                        if event.type == "DNS_NAME" and self.scan.ingress_module.is_incoming_duplicate(
                            event, add=True
                        ):
                            if not event._graph_important:
                                return (
                                    False,
                                    "it's a DNS wildcard, and its module already emitted a similar wildcard event",
                                )
                            else:
                                self.debug(
                                    f"Event {event} was already emitted by its module, but it's graph-important so it gets a pass"
                                )

        # if there weren't any DNS children and it's not an IP address, tag as unresolved
        # Exception: don't convert seed events to DNS_NAME_UNRESOLVED so accept_seeds modules can process them
        if not main_host_event.raw_dns_records and not event_is_ip:
            if "seed" not in main_host_event.tags:
                main_host_event.add_tag("unresolved")
                main_host_event.type = "DNS_NAME_UNRESOLVED"
                # avoid emitting DNS_NAME_UNRESOLVED affiliates
                main_host_event.always_emit_tags = []

        # main_host_event.add_tag(f"resolve-distance-{main_host_event.dns_resolve_distance}")

        dns_tags = main_host_event.tags.difference(original_tags)

        dns_resolve_distance = getattr(main_host_event, "dns_resolve_distance", 0)
        runaway_dns = dns_resolve_distance >= self.helpers.dns.runaway_limit
        if runaway_dns:
            # kill runaway DNS chains
            self.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.helpers.dns.runaway_limit})"
            )
            main_host_event.add_tag(f"runaway-dns-{dns_resolve_distance}")
        else:
            # graph-important events are edge-only re-emissions of an already-processed host;
            # skip re-walking their children (the canonical emission already did so, and
            # re-walking would re-emit the same cross-parent edges once per parent)
            if not event._graph_important:
                # emit dns children
                await self.emit_dns_children_raw(main_host_event, dns_tags)
                if not self.minimal:
                    await self.emit_dns_children(main_host_event)

            # emit the main DNS_NAME or IP_ADDRESS
            if (
                new_event
                and event is not main_host_event
                and main_host_event.scope_distance <= self._dns_search_distance
            ):
                await self.emit_event(main_host_event)

        # transfer scope distance to event
        event.scope_distance = main_host_event.scope_distance
        event._resolved_hosts = main_host_event.resolved_hosts

    async def handle_wildcard_event(self, event):
        rdtypes = tuple(event.raw_dns_records)
        wildcard_rdtypes = await self.helpers.is_wildcard(
            event.host, rdtypes=rdtypes, raw_dns_records=event.raw_dns_records
        )
        for rdtype, (is_wildcard, wildcard_host) in wildcard_rdtypes.items():
            if is_wildcard is False:
                continue
            elif is_wildcard is True:
                event.add_tag("wildcard")
                wildcard_tag = "wildcard"
            else:
                event.add_tag(f"wildcard-{is_wildcard}")
                wildcard_tag = f"wildcard-{is_wildcard}"
            event.add_tag(f"{rdtype}-{wildcard_tag}")

        # wildcard event modification (www.evilcorp.com --> _wildcard.evilcorp.com)
        if wildcard_rdtypes and "seed" not in event.tags:
            # these are the rdtypes that have wildcards
            wildcard_rdtypes_set = set(wildcard_rdtypes)
            # consider the event a full wildcard if all its records are wildcards
            event_is_wildcard = False
            if wildcard_rdtypes_set:
                event_is_wildcard = all(r[0] is True for r in wildcard_rdtypes.values())

            if event_is_wildcard:
                if event.type in ("DNS_NAME",) and "_wildcard" not in event.data.split("."):
                    wildcard_parent = self.helpers.parent_domain(event.host)
                    for rdtype, (_is_wildcard, _parent_domain) in wildcard_rdtypes.items():
                        if _is_wildcard:
                            wildcard_parent = _parent_domain
                            break
                    wildcard_data = f"_wildcard.{wildcard_parent}"
                    if wildcard_data != event.data:
                        self.debug(
                            f'Wildcard detected, changing event.data "{event.pretty_string}" --> "{wildcard_data}"'
                        )
                        event.data = wildcard_data
                        return True
        return False

    async def emit_dns_children(self, event):
        for rdtype, children in event.dns_children.items():
            module = self._make_dummy_module(rdtype)
            for child_host in children:
                try:
                    child_event = self.scan.make_event(
                        child_host,
                        # auto-detect the type; SPF TXT children can be IP_ADDRESS / IP_RANGE
                        None,
                        module=module,
                        parent=event,
                        context=f"{rdtype} record for {event.host} contains {{event.type}}: {{event.host}}",
                    )
                except ValidationError as e:
                    self.trace(f'Event validation failed for DNS child of {event}: "{child_host}" ({rdtype}): {e}')
                    continue

                # tag PTR-derived children so downstream logic can identify them
                if rdtype == "PTR":
                    child_event.add_tag("ptr")

                child_hash = hash(f"{module}:{child_host}")
                # if we haven't emitted this one before
                if child_hash not in self.children_emitted:
                    child_in_scope = self.preset.in_scope(child_host)
                    # and it's either in-scope or inside our dns search distance
                    if child_in_scope or child_event.scope_distance <= self._dns_search_distance:
                        self.children_emitted.add(child_hash)
                        if child_in_scope:
                            # remember in-scope children (so cross-parent dups are recognized without
                            # a second scope lookup) and record this parent->child edge
                            self.in_scope_children.add(child_hash)
                            self.child_edges_emitted.add(hash(f"{event.host}:{module}:{child_host}"))
                        # if it's a hostname and it's only one hop away, mark it as affiliate
                        if child_event.type == "DNS_NAME" and child_event.scope_distance == 1:
                            child_event.add_tag("affiliate")
                        self.debug(f"Queueing DNS child for {event}: {child_event}")
                        await self.emit_event(child_event)
                # the child entity was already emitted, but a genuinely new in-scope parent->child
                # edge is worth preserving for graph outputs (neo4j/json) so shared in-scope
                # infrastructure keeps every edge. out-of-scope dups and same-parent re-processing
                # stay collapsed (out-of-scope children never enter in_scope_children).
                elif child_hash in self.in_scope_children:
                    # parent-aware key: tells a genuinely new parent->child edge apart from the same
                    # host being re-processed (children_emitted drops the parent, so it can't)
                    edge_hash = hash(f"{event.host}:{module}:{child_host}")
                    if edge_hash not in self.child_edges_emitted:
                        self.child_edges_emitted.add(edge_hash)
                        # _graph_important must imply the event reaches output; an omitted type is
                        # dropped there regardless, so don't flag it (keeps _graph_important => not _omit)
                        if child_event.type not in self.scan.omitted_event_types:
                            child_event._graph_important = True
                            self.debug(f"Queueing graph-important DNS child edge for {event}: {child_event}")
                            await self.emit_event(child_event)

    async def emit_dns_children_raw(self, event, dns_tags):
        for rdtype, answers in event.raw_dns_records.items():
            rdtype_lower = rdtype.lower()
            tags = {t for t in dns_tags if rdtype_lower in t.split("-")}
            if self.emit_raw_records and rdtype not in ("A", "AAAA", "CNAME", "PTR"):
                for answer in answers:
                    text_answer = record_to_text(answer)
                    child_hash = hash(f"{event.host}:{rdtype}:{text_answer}")
                    if child_hash not in self.children_emitted_raw:
                        self.children_emitted_raw.add(child_hash)
                        await self.emit_event(
                            {"host": str(event.host), "type": rdtype, "answer": text_answer},
                            "RAW_DNS_RECORD",
                            parent=event,
                            tags=tags,
                            context=f"{rdtype} lookup on {{event.parent.host}} produced {{event.type}}",
                        )

    def check_scope(self, event):
        in_target = False
        blacklisted = False
        dns_children = event.dns_children
        # collect all resolved hosts locally then assign once; resolved_hosts
        # is naturally immutable (frozenset) and has no in-place mutation API
        all_hosts = set()
        for rdtype in ("A", "AAAA", "CNAME"):
            hosts = dns_children.get(rdtype, [])
            all_hosts.update(sys.intern(h) for h in hosts)
            for host in hosts:
                # having a CNAME to an in-scope host doesn't make you in-scope
                if rdtype != "CNAME":
                    if not in_target:
                        with suppress(ValidationError):
                            if self.scan.in_target(host):
                                in_target = True
                                event.add_tag(f"dns-in-target-{rdtype}")
                # but a CNAME to a blacklisted host means you're blacklisted
                if not blacklisted:
                    with suppress(ValidationError):
                        if self.scan.blacklisted(host):
                            blacklisted = True
                            event.add_tag("blacklisted")
                            event.add_tag(f"dns-blacklisted-{rdtype}")
        if all_hosts:
            event.resolved_hosts = all_hosts
        if blacklisted:
            in_target = False
        return in_target, blacklisted

    async def resolve_event(self, event, types):
        if not types:
            return
        event_host = str(event.host)
        results = await self.helpers.dns.resolve_multi_full(event_host, list(types))
        for rdtype, response in results.items():
            rdtype = sys.intern(rdtype)
            if not isinstance(response, DNSResult):
                # blastdns returns a DNSError for this rdtype; tag and move on
                if rdtype not in event.dns_children:
                    event.add_tag(f"{rdtype}-error")
                continue

            answers = response.response.answers
            if not answers:
                continue

            event.add_tag(f"{rdtype}-record")
            # blastdns hands us an already-unique list[Record] -- store as-is, no copy
            event.set_raw_dns_record(rdtype, answers)
            for answer in answers:
                for _rdtype, host in extract_targets(answer):
                    _rdtype = sys.intern(_rdtype)
                    host = sys.intern(host)
                    event.add_dns_child(_rdtype, host)
                    # check for private IPs
                    try:
                        ip = cached_ip_address(host)
                        if ip.is_private:
                            event.add_tag("private-ip")
                    except ValueError:
                        continue

    def get_dns_parent(self, event):
        """
        Get the first parent DNS_NAME / IP_ADDRESS of an event. If one isn't found, create it.

        Returns a 4-tuple of:
        - the parent event
        - whether the parent is in target
        - whether the parent is blacklisted
        - whether the parent is a new event, i.e. it is newly created or is the current event
        """
        for parent in event.get_parents(include_self=True):
            if parent.host == event.host and parent.type in ("IP_ADDRESS", "DNS_NAME", "DNS_NAME_UNRESOLVED"):
                blacklisted = any(t.startswith("dns-blacklisted-") for t in parent.tags)
                in_target = any(t.startswith("dns-in-target-") for t in parent.tags)
                new_event = parent is event
                return parent, in_target, blacklisted, new_event
        tags = set()
        if "seed" in event.tags:
            tags.add("seed")
        return (
            self.scan.make_event(
                event.host,
                "DNS_NAME",
                module=self.host_module,
                parent=event,
                context="{event.parent.type} has host {event.type}: {event.host}",
                tags=tags,
            ),
            None,
            None,
            True,
        )

    @property
    def emit_raw_records(self):
        if self._emit_raw_records is None:
            watching_raw_records = any("RAW_DNS_RECORD" in m.get_watched_events() for m in self.scan.modules.values())
            omitted_event_types = self.scan.config.get("omit_event_types", [])
            omit_raw_records = "RAW_DNS_RECORD" in omitted_event_types
            self._emit_raw_records = watching_raw_records or not omit_raw_records
        return self._emit_raw_records

    @property
    def _dns_search_distance(self):
        return max(self.scan.scope_search_distance, self.dns_search_distance)

    def _make_dummy_module(self, name):
        try:
            dummy_module = self.scan.dummy_modules[name]
        except KeyError:
            dummy_module = self.scan._make_dummy_module(name=name, _type="DNS")
            dummy_module._priority = 4
            dummy_module.suppress_dupes = False
            self.scan.dummy_modules[name] = dummy_module
        return dummy_module
