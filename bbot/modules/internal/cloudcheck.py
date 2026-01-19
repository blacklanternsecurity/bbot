import asyncio
import regex as re
from contextlib import suppress

from bbot.modules.base import BaseInterceptModule


class CloudCheck(BaseInterceptModule):
    watched_events = ["*"]
    meta = {
        "description": "Tag events by cloud provider, identify cloud resources like storage buckets",
        "created_date": "2024-07-07",
        "author": "@TheTechromancer",
    }
    # tag events up to and including distance-2
    scope_distance_modifier = 2
    _priority = 3

    async def setup(self):
        self._cloud_hostname_regexes = None
        self._cloud_hostname_regexes_lock = asyncio.Lock()
        return True

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, **kwargs):
        # cloud tagging by hosts
        hosts_to_check = set(event.resolved_hosts)
        with suppress(KeyError):
            hosts_to_check.remove(event.host_original)
        hosts_to_check = [str(event.host_original)] + list(hosts_to_check)

        for i, host in enumerate(hosts_to_check):
            host_is_ip = self.helpers.is_ip(host)
            try:
                cloudcheck_results = await self.helpers.cloudcheck.lookup(host)
            except Exception as e:
                self.trace(f"Error running cloudcheck against {event} (host: {host}): {e}")
                continue
            for provider in cloudcheck_results:
                provider_name = provider["name"].lower()
                tags = provider.get("tags", [])
                for tag in tags:
                    event.add_tag(tag)
                    event.add_tag(f"{tag}-{provider_name}")
                    if host_is_ip:
                        event.add_tag(f"{provider_name}-ip")
                    else:
                        # if the original hostname is a cloud domain, tag it as such
                        if i == 0:
                            event.add_tag(f"{provider_name}-domain")
                        # any children are tagged as CNAMEs
                        else:
                            event.add_tag(f"{provider_name}-cname")

        # we only generate storage buckets off of in-scope or distance-1 events
        if event.scope_distance >= self.max_scope_distance:
            return

        # see if any of our hosts are storage buckets, etc.
        regexes = await self.cloud_hostname_regexes()
        regexes = regexes.get("STORAGE_BUCKET_HOSTNAME", [])
        for regex_name, regex in regexes.items():
            for host in hosts_to_check:
                if match := regex.match(host):
                    try:
                        bucket_name, bucket_domain = match.groups()
                    except Exception as e:
                        self.error(
                            f"Bucket regex {regex_name} ({regex}) is not formatted correctly to extract bucket name and domain: {e}"
                        )
                        continue
                    bucket_name, bucket_domain = match.groups()
                    bucket_url = f"https://{bucket_name}.{bucket_domain}"
                    await self.emit_event(
                        {
                            "name": bucket_name,
                            "url": bucket_url,
                            "context": f"{{module}} analyzed {event.type} and found {{event.type}}: {bucket_url}",
                        },
                        "STORAGE_BUCKET",
                        parent=event,
                    )

    async def cloud_hostname_regexes(self):
        async with self._cloud_hostname_regexes_lock:
            if not self._cloud_hostname_regexes:
                storage_bucket_regexes = {}
                self._cloud_hostname_regexes = {"STORAGE_BUCKET_HOSTNAME": storage_bucket_regexes}
                from cloudcheck import providers

                for attr in dir(providers):
                    if attr.startswith("_"):
                        continue
                    provider = getattr(providers, attr)
                    provider_regexes = getattr(provider, "regexes", {})
                    for regex_name, regexes in provider_regexes.items():
                        for i, regex in enumerate(regexes):
                            if not regex_name in ("STORAGE_BUCKET_HOSTNAME"):
                                continue
                            try:
                                storage_bucket_regexes[f"{attr}-{regex_name}-{i}"] = re.compile(regex)
                            except Exception as e:
                                self.error(f"Error compiling regex for {attr}-{regex_name}: {e}")
                                continue
            return self._cloud_hostname_regexes
