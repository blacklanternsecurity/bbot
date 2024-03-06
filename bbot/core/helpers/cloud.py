import asyncio
import logging

from cloudcheck import cloud_providers

log = logging.getLogger("bbot.helpers.cloud")


class CloudHelper:
    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.providers = cloud_providers
        self._updated = False
        self._update_lock = asyncio.Lock()

    def excavate(self, event, s):
        """
        Extract buckets, etc. from strings such as an HTTP responses
        """
        for provider in self:
            provider_name = provider.name.lower()
            base_kwargs = {"source": event, "tags": [f"cloud-{provider_name}"], "_provider": provider_name}
            for event_type, sigs in provider.signatures.items():
                found = set()
                for sig in sigs:
                    for match in sig.findall(s):
                        kwargs = dict(base_kwargs)
                        kwargs["event_type"] = event_type
                        if not match in found:
                            found.add(match)
                            if event_type == "STORAGE_BUCKET":
                                self.emit_bucket(match, **kwargs)
                            else:
                                yield kwargs

    def speculate(self, event):
        """
        Look for DNS_NAMEs that are buckets or other cloud resources
        """
        for provider in self:
            provider_name = provider.name.lower()
            base_kwargs = dict(
                source=event, tags=[f"{provider.provider_type}-{provider_name}"], _provider=provider_name
            )
            if event.type.startswith("DNS_NAME"):
                for event_type, sigs in provider.signatures.items():
                    found = set()
                    for sig in sigs:
                        match = sig.match(event.data)
                        if match:
                            kwargs = dict(base_kwargs)
                            kwargs["event_type"] = event_type
                            if not event.data in found:
                                found.add(event.data)
                                if event_type == "STORAGE_BUCKET":
                                    yield self.emit_bucket(match.groups(), **kwargs)
                                else:
                                    yield kwargs

    async def emit_bucket(self, match, **kwargs):
        bucket_name, bucket_domain = match
        kwargs["data"] = {"name": bucket_name, "url": f"https://{bucket_name}.{bucket_domain}"}
        return kwargs

    async def tag_event(self, event):
        """
        Tags an event according to cloud provider
        """
        async with self._update_lock:
            if not self._updated:
                await self.providers.update()
                self._updated = True

        if event.host:
            for host in [event.host] + list(event.resolved_hosts):
                provider_name, provider_type, source = self.providers.check(host)
                if provider_name is not None:
                    provider = self.providers.providers[provider_name.lower()]
                    event.add_tag(f"{provider_type}-{provider_name.lower()}")
                    # if its host directly matches this cloud provider's domains
                    if not self.parent_helper.is_ip(host):
                        # tag as buckets, etc.
                        for event_type, sigs in provider.signatures.items():
                            for sig in sigs:
                                if sig.match(host):
                                    event.add_tag(f"{provider_type}-{event_type}")

    def __getitem__(self, item):
        return self.providers.providers[item.lower()]

    def __iter__(self):
        yield from self.providers
