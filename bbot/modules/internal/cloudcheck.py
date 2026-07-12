import regex as re
import yara
from contextlib import suppress

from cachetools import LRUCache

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

    # LRU cache for cloudcheck.lookup() results. Many subdomains in a single
    # scan resolve to the same backing IPs (e.g. all *.cloudfront.net entries
    # share the same handful of CF IPs), so the same host gets looked up many
    # times. Caching the result is ~600x faster than re-issuing the Future-
    # based lookup. Sized to target ~50MB at average ~500 B / entry — most
    # entries are an empty list (no cloud match) and small.
    _lookup_cache_size = 100_000

    async def setup(self):
        # perform a test lookup during setup to force signature update.
        # if cloudcheck can't fetch its signatures (e.g. network/TLS problem,
        # offline), don't crash the scan — degrade gracefully. cloud tagging
        # by IP/domain will be unavailable, but static storage-bucket regexes
        # (loaded from the cloudcheck package below) and per-event lookups
        # (already wrapped in try/except) keep working.
        from cloudcheck import CloudCheckError

        try:
            await self.helpers.cloudcheck.lookup("8.8.8.8")
        except CloudCheckError as e:
            self.warning(
                f"Failed to load cloud provider signatures ({e}); continuing with cloud detection degraded. "
                f"If this is caused by a TLS-intercepting proxy on a network you trust, you can set "
                f"ssl_verify_infrastructure: false to allow the fetch — note this turns off certificate "
                f"verification for non-target traffic, so only do so if you understand the risk."
            )
        # build the storage-bucket regexes + the YARA prefilter eagerly so we
        # don't pay an asyncio.Lock acquire on every handle_event
        self._storage_bucket_regexes, self._bucket_yara = self._build_bucket_matchers()
        self._lookup_cache = LRUCache(maxsize=self._lookup_cache_size)
        return True

    async def _cached_lookup(self, host):
        """Cache cloudcheck.lookup() results by host. The underlying lookup
        is deterministic (host -> set of providers) for the duration of a
        scan, so a simple per-scan LRU is correct."""
        try:
            return self._lookup_cache[host]
        except KeyError:
            pass
        result = await self.helpers.cloudcheck.lookup(host)
        self._lookup_cache[host] = result
        return result

    def _build_bucket_matchers(self):
        """
        Build two structures from the cloudcheck providers' bucket regexes:

        - `storage_bucket_regexes`: dict of name -> compiled Python regex
          (with named groups intact). Used to extract `name` / `region` from
          a host once we know it matched.
        - `bucket_yara`: a single compiled YARA rule that ORs every bucket
          pattern together (named groups stripped, since YARA's regex
          flavor doesn't support `?P<...>`). Used as a fast prefilter — if
          none of its strings hit, we skip the Python-regex loop entirely.
        """
        from cloudcheck import providers

        storage_bucket_regexes = {}
        yara_strings = []
        for attr in dir(providers):
            if attr.startswith("_"):
                continue
            provider = getattr(providers, attr)
            provider_regexes = getattr(provider, "regexes", None)
            if not provider_regexes:
                continue
            for i, pattern in enumerate(provider_regexes.get("STORAGE_BUCKET_HOSTNAME", [])):
                key = f"{attr}-STORAGE_BUCKET_HOSTNAME-{i}"
                try:
                    storage_bucket_regexes[key] = re.compile(pattern)
                except Exception as e:
                    self.error(f"Error compiling regex for {key}: {e}")
                    continue
                # YARA accepts the pattern as-is once we strip the named-group
                # syntax (`?P<name>` / `?P<region>` aren't part of YARA's regex
                # flavor; the unnamed-group form matches the same strings).
                yara_pattern = pattern.replace("(?P<name>", "(").replace("(?P<region>", "(")
                yara_strings.append(f"$bucket_{len(yara_strings)} = /{yara_pattern}/")

        if yara_strings:
            yara_source = (
                "rule storage_buckets {\n"
                "    strings:\n        " + "\n        ".join(yara_strings) + "\n"
                "    condition: any of them\n"
                "}"
            )
            try:
                bucket_yara = yara.compile(source=yara_source)
            except yara.SyntaxError as e:
                self.error(f"Failed to compile bucket YARA rule: {e}; falling back to regex-only matching")
                bucket_yara = None
        else:
            bucket_yara = None

        return storage_bucket_regexes, bucket_yara

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

        # Inheritance fast path: if our parent has already been through cloudcheck
        # and its host set covers ours, copy its cloud tags and host_metadata
        # entries instead of re-running the lookups. This is common in event
        # chains where multiple types (DNS_NAME -> IP_ADDRESS -> OPEN_TCP_PORT
        # -> URL) carry hosts that are a subset of the parent's resolved set.
        inherited = self._inherit_cloud_tags(event, hosts_to_check)
        if not inherited:
            for i, host in enumerate(hosts_to_check):
                host_is_ip = self.helpers.is_ip(host)
                try:
                    cloudcheck_results = await self._cached_lookup(host)
                except Exception as e:
                    self.warning(f"Error running cloudcheck against {event} (host: {host}): {e}")
                    continue
                for provider in cloudcheck_results:
                    provider_name = provider["name"].lower()
                    provider_types = provider.get("tags", [])
                    for provider_type in provider_types:
                        event.add_tag(provider_type)
                    event.add_tag(provider_name)
                    # determine how the match was triggered
                    if host_is_ip:
                        match_type = "ip"
                    elif i == 0:
                        match_type = "domain"
                    else:
                        match_type = "cname"
                    # structured details in host_metadata
                    host_meta = event.host_metadata.setdefault(host, {})
                    cloud_providers = host_meta.setdefault("cloud_providers", {})
                    cloud_providers[provider_name] = {
                        "types": sorted(set(provider_types)),
                        "match": match_type,
                    }

        # mark this event so descendants can inherit our cloud tags;
        # resolved_hosts is naturally immutable so descendants can trust
        # parent.resolved_hosts directly without a snapshot
        event._cloudcheck_done = True

        # we only generate storage buckets off of in-scope or distance-1 events
        if event.scope_distance >= self.max_scope_distance:
            return

        # storage-bucket hostnames are anchored to provider-specific suffixes
        # (e.g. .amazonaws.com), so they can never match a bare IP literal
        if all(self.helpers.is_ip(h) for h in hosts_to_check):
            return

        # YARA prefilter: run all bucket patterns simultaneously against the
        # joined hosts. ~95% of events have no host that could possibly match,
        # and YARA returns no matches in one optimized scan — skipping the
        # per-regex Python loop entirely. Only on a hit do we run the full
        # per-regex pass below to extract the named `name` / `region` groups.
        if self._bucket_yara is not None:
            if not self._bucket_yara.match(data="\n".join(hosts_to_check)):
                return

        # at least one host *could* be a bucket — run the per-regex extraction
        for regex_name, regex in self._storage_bucket_regexes.items():
            for host in hosts_to_check:
                if match := regex.match(host):
                    groups = match.groupdict()
                    bucket_name = groups.get("name")
                    if not bucket_name:
                        self.error(f"Bucket regex {regex_name} ({regex.pattern}) did not yield a 'name' group")
                        continue
                    region = groups.get("region")
                    bucket_url = f"https://{host}"
                    bucket_data = {
                        "name": bucket_name,
                        "url": bucket_url,
                        "context": f"{{module}} analyzed {event.type} and found {{event.type}}: {bucket_url}",
                    }
                    if region:
                        bucket_data["region"] = region
                    await self.emit_event(bucket_data, "STORAGE_BUCKET", parent=event)

    def _inherit_cloud_tags(self, event, hosts_to_check):
        """
        If `event`'s parent has already been through cloudcheck and its host
        set covers ours, copy the parent's per-host cloud metadata into ours
        for the hosts we share. Returns True if inheritance was applied
        (caller can skip the lookup phase).

        Safe because `resolved_hosts` is naturally immutable after dnsresolve
        finalizes an event — no module can retroactively add a host that the
        parent never looked up.

        We iterate `parent.host_metadata` (only matched hosts; typically zero
        or one entries) rather than the child's full `hosts_to_check`. When
        parent has no matches we do no work beyond the subset gate.
        """
        parent = event.get_parent()
        if parent is None or parent is event or not getattr(parent, "_cloudcheck_done", False):
            return False
        parent_host = parent.host_original
        if parent_host is None:
            return False

        # subset gate: parent's host set must cover ours, otherwise parent's
        # "no match" results aren't reliable for hosts parent never looked up
        my_hosts = set(hosts_to_check)
        parent_hosts = set(parent.resolved_hosts)
        parent_hosts.add(str(parent_host))
        if not my_hosts.issubset(parent_hosts):
            return False

        # walk parent's matched hosts; copy only ones we share, recompute
        # `match` from child's perspective (position-independent: "domain"
        # is just "this host equals our host_original")
        parent_meta = getattr(parent, "_host_metadata", None)
        if parent_meta:
            event_host_original = event.host_original
            for host, host_data in parent_meta.items():
                if host not in my_hosts:
                    continue
                cloud_providers = host_data.get("cloud_providers")
                if not cloud_providers:
                    continue
                if self.helpers.is_ip(host):
                    match_type = "ip"
                elif host == event_host_original:
                    match_type = "domain"
                else:
                    match_type = "cname"
                my_host_data = event.host_metadata.setdefault(host, {})
                my_cloud_providers = my_host_data.setdefault("cloud_providers", {})
                for provider_name, info in cloud_providers.items():
                    # fresh dict — never share parent's inner objects
                    my_cloud_providers[provider_name] = {
                        "types": list(info.get("types", [])),
                        "match": match_type,
                    }
                    event.add_tag(provider_name)
                    for tag in info.get("types", []):
                        event.add_tag(tag)
        return True
