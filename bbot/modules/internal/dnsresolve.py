from contextlib import suppress

from bbot.errors import ValidationError
from bbot.modules.base import HookModule


class dnsresolve(HookModule):
    watched_events = ["*"]
    _priority = 1

    async def setup(self):
        self.dns_resolution = self.scan.config.get("dns_resolution", False)
        self.scope_search_distance = max(0, int(self.config.get("scope_search_distance", 0)))
        self.scope_dns_search_distance = max(0, int(self.config.get("scope_dns_search_distance", 1)))
        self.scope_distance_modifier = max(self.scope_search_distance, self.scope_dns_search_distance)
        return True

    async def filter_event(self, event):
        if not event.host:
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event):
        self.hugesuccess(event)
        # skip DNS resolution if it's disabled in the config and the event is a target and we don't have a blacklist
        # this is a performance optimization and it'd be nice if we could do it for all events not just targets
        # but for non-target events, we need to know what IPs they resolve to so we can make scope decisions about them
        skip_dns_resolution = (not self.dns_resolution) and "target" in event.tags and not self.scan.blacklist
        if skip_dns_resolution:
            dns_tags = {"resolved"}
            dns_children = dict()
        else:
            # DNS resolution
            dns_tags, dns_children = await self.helpers.dns.resolve_event(event, minimal=not self.dns_resolution)

        # whitelisting / blacklisting based on resolved hosts
        event_whitelisted = False
        event_blacklisted = False
        for rdtype, children in dns_children.items():
            self.hugeinfo(f"{event.host}: {rdtype}:{children}")
            if event_blacklisted:
                break
            for host in children:
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
            return

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
                await self.emit_event(source_event)

        ### Emit DNS children ###
        if self.dns_resolution:
            self.hugesuccess(f"emitting children for {event}! (dns children: {event.dns_children})")
            emit_children = True
            in_dns_scope = -1 < event.scope_distance < self.scope_distance_modifier
            self.critical(f"{event.host} in dns scope: {in_dns_scope}")

            if emit_children:
                dns_child_events = []
                if event.dns_children:
                    for rdtype, records in event.dns_children.items():
                        self.hugewarning(f"{event.host}: {rdtype}:{records}")
                        module = self.scan._make_dummy_module_dns(rdtype)
                        module._priority = 4
                        for record in records:
                            try:
                                child_event = self.scan.make_event(
                                    record, "DNS_NAME", module=module, source=source_event
                                )
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
                    await self.emit_event(child_event)
