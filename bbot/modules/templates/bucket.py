from bbot.modules.base import BaseModule


class bucket_template(BaseModule):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }
    scope_distance_modifier = 3

    cloud_helper_name = "amazon|google|digitalocean|etc"
    delimiters = ("", ".", "-")
    base_domains = ["s3.amazonaws.com|digitaloceanspaces.com|etc"]
    regions = [None]
    supports_open_check = True

    async def setup(self):
        self.buckets_tried = set()
        self.cloud_helper = self.helpers.cloud.providers[self.cloud_helper_name]
        self.permutations = self.config.get("permutations", False)
        return True

    async def filter_event(self, event):
        if event.type == "DNS_NAME" and event.scope_distance > 0:
            return False, "only accepts in-scope DNS_NAMEs"
        if event.type == "STORAGE_BUCKET":
            filter_result, reason = self.filter_bucket(event)
            if not filter_result:
                return (filter_result, reason)
        return True

    def filter_bucket(self, event):
        if f"cloud-{self.cloud_helper_name}" not in event.tags:
            return False, "bucket belongs to a different cloud provider"
        return True, ""

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_dns_name(event)
        elif event.type == "STORAGE_BUCKET":
            await self.handle_storage_bucket(event)

    async def handle_dns_name(self, event):
        buckets = set()
        base = self.helpers.unidecode(self.helpers.smart_decode_punycode(event.data))
        stem = self.helpers.domain_stem(base)
        for b in [base, stem]:
            split = b.split(".")
            for d in self.delimiters:
                bucket_name = d.join(split)
                buckets.add(bucket_name)
        async for bucket_name, url, tags, num_buckets in self.brute_buckets(buckets, permutations=self.permutations):
            await self.emit_storage_bucket(
                {"name": bucket_name, "url": url},
                "STORAGE_BUCKET",
                parent=event,
                tags=tags,
                context=f"{{module}} tried {num_buckets:,} bucket variations of {event.data} and found {{event.type}} at {url}",
            )

    async def handle_storage_bucket(self, event):
        url = event.data["url"]
        bucket_name = event.data["name"]
        if self.supports_open_check:
            description, tags = await self._check_bucket_open(bucket_name, url)
            if description:
                event_data = {"host": event.host, "url": url, "description": description}
                await self.emit_event(
                    event_data,
                    "FINDING",
                    parent=event,
                    tags=tags,
                    context=f"{{module}} scanned {event.type} and identified {{event.type}}: {description}",
                )

        async for bucket_name, new_url, tags, num_buckets in self.brute_buckets(
            [bucket_name], permutations=self.permutations, omit_base=True
        ):
            await self.emit_storage_bucket(
                {"name": bucket_name, "url": new_url},
                "STORAGE_BUCKET",
                parent=event,
                tags=tags,
                context=f"{{module}} tried {num_buckets:,} variations of {url} and found {{event.type}} at {new_url}",
            )

    async def emit_storage_bucket(self, event_data, event_type, parent, tags, context):
        event_data["url"] = self.clean_bucket_url(event_data["url"])
        await self.emit_event(
            event_data,
            event_type,
            parent=parent,
            tags=tags,
            context=context,
        )

    async def brute_buckets(self, buckets, permutations=False, omit_base=False):
        buckets = set(buckets)
        new_buckets = set(buckets)
        if permutations:
            for b in buckets:
                for mutation in self.helpers.word_cloud.mutations(b, cloud=False):
                    for d in self.delimiters:
                        new_buckets.add(d.join(mutation))
        if omit_base:
            new_buckets = new_buckets - buckets
        new_buckets = [b for b in new_buckets if self.valid_bucket_name(b)]
        num_buckets = len(new_buckets)
        bucket_urls_kwargs = []
        for base_domain in self.base_domains:
            for region in self.regions:
                for bucket_name in new_buckets:
                    url, kwargs = self.build_bucket_request(bucket_name, base_domain, region)
                    bucket_urls_kwargs.append((url, kwargs, (bucket_name, base_domain, region)))
        async for url, kwargs, (bucket_name, base_domain, region), response in self.helpers.request_custom_batch(
            bucket_urls_kwargs
        ):
            existent_bucket, tags = self._check_bucket_exists(bucket_name, response)
            if existent_bucket:
                yield bucket_name, url, tags, num_buckets

    def clean_bucket_url(self, url):
        # if needed, modify the bucket url before emitting it
        return url

    def build_bucket_request(self, bucket_name, base_domain, region):
        url = self.build_url(bucket_name, base_domain, region)
        return url, {}

    def _check_bucket_exists(self, bucket_name, response):
        self.debug(f'Checking if bucket exists: "{bucket_name}"')
        return self.check_bucket_exists(bucket_name, response)

    def check_bucket_exists(self, bucket_name, response):
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        existent_bucket = status_code != 404
        return (existent_bucket, tags)

    async def _check_bucket_open(self, bucket_name, url):
        self.debug(f'Checking if bucket is misconfigured: "{bucket_name}"')
        return await self.check_bucket_open(bucket_name, url)

    async def check_bucket_open(self, bucket_name, url):
        response = await self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        content = getattr(response, "text", "")
        open_bucket = status_code == 200 and "Contents" in content
        msg = ""
        if open_bucket:
            msg = "Open storage bucket"
        return (msg, tags)

    def valid_bucket_name(self, bucket_name):
        valid = self.cloud_helper.is_valid_bucket_name(bucket_name)
        if valid and not self.helpers.is_ip(bucket_name):
            bucket_hash = hash(bucket_name)
            if bucket_hash not in self.buckets_tried:
                self.buckets_tried.add(bucket_hash)
                return True
        return False

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{base_domain}/"

    def gen_tags_exists(self, response):
        return set()

    def gen_tags_open(self, response):
        return set()
