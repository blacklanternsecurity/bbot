from contextlib import suppress

from bbot.modules.base import BaseInterceptModule


class CloudCheck(BaseInterceptModule):
    watched_events = ["*"]
    meta = {
        "description": "Tag events by cloud provider, identify cloud resources like storage buckets",
        "created_date": "2024-07-07",
        "author": "@TheTechromancer",
    }
    scope_distance_modifier = 1
    _priority = 3

    async def setup(self):
        self.dummy_modules = None
        return True

    def make_dummy_modules(self):
        self.dummy_modules = {}
        for provider_name in self.helpers.cloud.providers.keys():
            module = self.scan._make_dummy_module(f"cloud_{provider_name}", _type="scan")
            module.default_discovery_context = "{module} derived {event.type}: {event.host}"
            self.dummy_modules[provider_name] = module

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, **kwargs):
        # don't hold up the event loop loading cloud IPs etc.
        if self.dummy_modules is None:
            self.make_dummy_modules()
        # cloud tagging by hosts
        hosts_to_check = set(event.resolved_hosts)
        with suppress(KeyError):
            hosts_to_check.remove(event.host_original)
        hosts_to_check = [event.host_original] + list(hosts_to_check)

        for i, host in enumerate(hosts_to_check):
            host_is_ip = self.helpers.is_ip(host)
            try:
                cloudcheck_results = self.helpers.cloudcheck(host)
            except Exception as e:
                self.trace(f"Error running cloudcheck against {event} (host: {host}): {e}")
                continue
            for provider, provider_type, subnet in cloudcheck_results:
                if provider:
                    event.add_tag(f"{provider_type}-{provider}")
                    if host_is_ip:
                        event.add_tag(f"{provider_type}-ip")
                    else:
                        # if the original hostname is a cloud domain, tag it as such
                        if i == 0:
                            event.add_tag(f"{provider_type}-domain")
                        # any children are tagged as CNAMEs
                        else:
                            event.add_tag(f"{provider_type}-cname")

        found = set()
        str_hosts_to_check = [str(host) for host in hosts_to_check]
        # look for cloud assets in hosts, http responses
        # loop through each provider
        for provider in self.helpers.cloud.providers.values():
            provider_name = provider.name.lower()
            base_kwargs = {
                "parent": event,
                "tags": [f"{provider.provider_type}-{provider_name}"],
                "_provider": provider_name,
            }
            # loop through the provider's regex signatures, if any
            for event_type, sigs in provider.signatures.items():
                if event_type != "STORAGE_BUCKET":
                    raise ValueError(f'Unknown cloudcheck event type "{event_type}"')
                base_kwargs["event_type"] = event_type
                for sig in sigs:
                    matches = []
                    # TODO: convert this to an excavate YARA hook
                    # if event.type == "HTTP_RESPONSE":
                    #     matches = await self.helpers.re.findall(sig, event.data.get("body", ""))
                    if event.type.startswith("DNS_NAME"):
                        for host in str_hosts_to_check:
                            match = sig.match(host)
                            if match:
                                matches.append(match.groups())
                    for match in matches:
                        if match not in found:
                            found.add(match)

                            _kwargs = dict(base_kwargs)
                            event_type_tag = f"cloud-{event_type}"
                            _kwargs["tags"].append(event_type_tag)
                            if event.type.startswith("DNS_NAME"):
                                event.add_tag(event_type_tag)

                            if event_type == "STORAGE_BUCKET":
                                bucket_name, bucket_domain = match
                                bucket_url = f"https://{bucket_name}.{bucket_domain}"
                                _kwargs["data"] = {
                                    "name": bucket_name,
                                    "url": bucket_url,
                                    "context": f"{{module}} analyzed {event.type} and found {{event.type}}: {bucket_url}",
                                }
                                await self.emit_event(**_kwargs)

    async def emit_event(self, *args, **kwargs):
        provider_name = kwargs.pop("_provider")
        dummy_module = self.dummy_modules[provider_name]
        event = dummy_module.make_event(*args, **kwargs)
        if event:
            await super().emit_event(event)
