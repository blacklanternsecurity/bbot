from bbot.modules.base import HookModule


class cloudcheck(HookModule):
    watched_events = ["*"]
    scope_distance_modifier = 1
    _priority = 3

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, kwargs):

        # skip if we're in tests
        if self.helpers.in_tests:
            return

        # cloud tagging by main host
        await self.scan.helpers.cloud.tag_event(event)

        # cloud tagging by resolved hosts
        to_check = set()
        if event.type == "IP_ADDRESS":
            to_check.add(event.host)
        for rdtype, hosts in event.dns_children.items():
            if rdtype in ("A", "AAAA"):
                for host in hosts:
                    to_check.add(host)
        for host in to_check:
            provider, provider_type, subnet = self.helpers.cloudcheck(host)
            if provider:
                event.add_tag(f"{provider_type}-{provider}")
