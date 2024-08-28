import ipaddress
from contextlib import suppress
from cachetools import LFUCache

from bbot.errors import ValidationError
from bbot.core.helpers.dns.engine import all_rdtypes
from bbot.core.helpers.async_helpers import NamedLock
from bbot.modules.base import InterceptModule, BaseModule
from bbot.core.helpers.dns.helpers import extract_targets


class DNSResolve(InterceptModule):
    """
    TODO:
        - scrap event cache in favor of the parent backtracking method (actual event should have all the information)
        - don't duplicate resolution on the same host
        - clean up wildcard checking to only happen once, and re-emit/abort if one is detected
            - same thing with main_host_event. we should never be processing two events - only one.
        - do not emit any hosts/children/raw until after scope checks
            - and only emit them if they're inside scope distance
            - order: A/AAAA --> scope check --> then rest?
    """

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
        self.minimal_rdtypes = ("A", "AAAA", "CNAME")
        self.non_minimal_rdtypes = [t for t in all_rdtypes if t not in self.minimal_rdtypes]
        self.dns_search_distance = max(0, int(self.dns_config.get("search_distance", 1)))
        self._emit_raw_records = None

        # event resolution cache
        self._event_cache = LFUCache(maxsize=10000)
        self._event_cache_locks = NamedLock()

        self.host_module = self.HostModule(self.scan)

        return True

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, **kwargs):
        raw_records = {}
        event_is_ip = self.helpers.is_ip(event.host)
        main_host_event, whitelisted, blacklisted, new_event = self.get_dns_parent(event)

        # minimal resolution - first, we resolve A/AAAA records for scope purposes
        if new_event or event is main_host_event:
            if event_is_ip:
                basic_records = await self.resolve_event(main_host_event, types=("PTR",))
            else:
                basic_records = await self.resolve_event(main_host_event, types=self.minimal_rdtypes)
                # are any of its IPs whitelisted/blacklisted?
                whitelisted, blacklisted = self.check_scope(main_host_event)
                if whitelisted and event.scope_distance > 0:
                    self.debug(
                        f"Making {main_host_event} in-scope because it resolves to an in-scope resource (A/AAAA)"
                    )
                    main_host_event.scope_distance = 0
            raw_records.update(basic_records)

        # abort if the event resolves to something blacklisted
        if blacklisted:
            return False, "it has a blacklisted DNS record"

        # are we within our dns search distance?
        within_dns_distance = main_host_event.scope_distance <= self._dns_search_distance
        within_scope_distance = main_host_event.scope_distance <= self.scan.scope_search_distance

        # if so, resolve the rest of our records
        if not event_is_ip:
            if (not self.minimal) and within_dns_distance:
                records = await self.resolve_event(main_host_event, types=self.minimal_rdtypes)
                raw_records.update(records)
            # check for wildcards if we're within the scan's search distance
            if new_event and within_scope_distance:
                await self.handle_wildcard_event(main_host_event)

        # kill runaway DNS chains
        # TODO: test this
        dns_resolve_distance = getattr(event, "dns_resolve_distance", 0)
        runaway_dns = dns_resolve_distance >= self.helpers.dns.runaway_limit
        if runaway_dns:
            self.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.helpers.dns.runaway_limit})"
            )
        else:
            if within_dns_distance:
                pass
                # emit dns children
                # emit raw records
                # emit host event

        # update host event --> event

    def check_scope(self, event):
        whitelisted = False
        blacklisted = False
        dns_children = getattr(event, "dns_children", {})
        for rdtype in ("A", "AAAA", "CNAME"):
            hosts = dns_children.get(rdtype, [])
            # update resolved hosts
            event.resolved_hosts.update(hosts)
            for host in hosts:
                # having a CNAME to an in-scope resource doesn't make you in-scope
                if rdtype != "CNAME":
                    if not whitelisted:
                        with suppress(ValidationError):
                            if self.scan.whitelisted(host):
                                whitelisted = True
                                event.add_tag(f"dns-whitelisted-{rdtype}")
                if not blacklisted:
                    with suppress(ValidationError):
                        if self.scan.blacklisted(host):
                            blacklisted = True
                            event.add_tag("blacklisted")
                            event.add_tag(f"dns-blacklisted-{rdtype}")
        if blacklisted:
            whitelisted = False
        return whitelisted, blacklisted

    async def resolve_event(self, event, types):
        raw_records = {}
        event_host = str(event.host)
        queries = [(event_host, rdtype) for rdtype in types]
        dns_errors = {}
        async for (query, rdtype), (answer, errors) in self.helpers.dns.resolve_raw_batch(queries):
            try:
                dns_errors[rdtype].update(errors)
            except KeyError:
                dns_errors[rdtype] = set(errors)
            # raw dnspython objects
            try:
                raw_records[rdtype].add(answer)
            except KeyError:
                raw_records[rdtype] = {answer}
            # hosts
            for _rdtype, host in extract_targets(answer):
                event.add_tag(f"{_rdtype}-record")
                try:
                    event.dns_children[_rdtype].add(host)
                except KeyError:
                    event.dns_children[_rdtype] = {host}
        # tag event with errors
        for rdtype, errors in dns_errors.items():
            # only consider it an error if there weren't any results for that rdtype
            if errors and not rdtype in event.dns_children:
                event.add_tag(f"{rdtype}-error")
        return raw_records

    async def handle_wildcard_event(self, event):
        pass

    def get_dns_parent(self, event):
        """
        Get the first parent DNS_NAME / IP_ADDRESS of an event. If one isn't found, create it.
        """
        for parent in event.get_parents(include_self=True):
            if parent.host == event.host and parent.type in ("IP_ADDRESS", "DNS_NAME", "DNS_NAME_UNRESOLVED"):
                blacklisted = any(t.startswith("dns-blacklisted-") for t in parent.tags)
                whitelisted = any(t.startswith("dns-whitelisted-") for t in parent.tags)
                return parent, whitelisted, blacklisted, False
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
        ), None, None, True

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

    def _dns_child_dedup_hash(self, parent_host, host, rdtype):
        # we deduplicate NS records by their parent domain
        # because otherwise every DNS_NAME has one, and it gets super messy
        if rdtype == "NS":
            _, parent_domain = self.helpers.split_domain(parent_host)
            return hash(f"{parent_domain}:{host}")
        return hash(f"{parent_host}:{host}:{rdtype}")

    def _main_outgoing_dedup_hash(self, event):
        return hash(f"{event.host}")
