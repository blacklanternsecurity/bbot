from bbot.modules.base import HookModule


class dnsresolve(HookModule):
    hooked_events = ["DNS_NAME"]
    _priority = 1

    async def setup(self):
        self.dns_resolution = self.scan.config.get("dns_resolution", False)
        return True

    async def handle_event(self, event):
        event.add_tag("dnsresolved")
        resolved_hosts = set()
        dns_children = {}
        dns_tags = set()

        # skip DNS resolution if it's disabled in the config and the event is a target and we don't have a blacklist
        # this is a performance optimization and it'd be nice if we could do it for all events not just targets
        # but for non-target events, we need to know what IPs they resolve to so we can make scope decisions about them
        skip_dns_resolution = (not self.dns_resolution) and "target" in event.tags and not self.scan.blacklist
        if skip_dns_resolution:
            dns_tags = {"resolved"}
        else:
            # DNS resolution
            dns_tags, dns_children = await self.helpers.dns.resolve_event(event, minimal=not self.dns_resolution)

        # whitelisting / blacklisting based on resolved hosts
        event_whitelisted = False
        event_blacklisted = False
        for rdtype, children in dns_children.items():
            if event_blacklisted:
                break
            for host in children:
                if rdtype in ("A", "AAAA", "CNAME"):
                    for ip in ips:
                        resolved_hosts.add(ip)
                    # having a CNAME to an in-scope resource doesn't make you in-scope
                    if not event_whitelisted and rdtype != "CNAME":
                        with suppress(ValidationError):
                            if self.parent_helper.scan.whitelisted(host):
                                event_whitelisted = True
                    # CNAME to a blacklisted resources, means you're blacklisted
                    with suppress(ValidationError):
                        if self.parent_helper.scan.blacklisted(host):
                            event_blacklisted = True
                            break

        # kill runaway DNS chains
        dns_resolve_distance = getattr(event, "dns_resolve_distance", 0)
        if dns_resolve_distance >= self.helpers.dns.max_dns_resolve_distance:
            log.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.scan.helpers.dns.max_dns_resolve_distance})"
            )
            dns_children = {}

        if event.type in ("DNS_NAME", "IP_ADDRESS"):
            event._dns_children = dns_children
            for tag in dns_tags:
                event.add_tag(tag)

        event._resolved_hosts = resolved_hosts

        event_whitelisted = event_whitelisted_dns | self.scan.whitelisted(event)
        event_blacklisted = event_blacklisted_dns | self.scan.blacklisted(event)
        if event_blacklisted:
            event.add_tag("blacklisted")
            reason = "event host"
            if event_blacklisted_dns:
                reason = "DNS associations"
            log.debug(f"Omitting due to blacklisted {reason}: {event}")
            return

        if event_whitelisted:
            event.add_tag("whitelisted")
