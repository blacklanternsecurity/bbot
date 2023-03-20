from bbot.modules.base import BaseModule


class bucket_aws(BaseModule):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic", "web-thorough"]
    meta = {"description": "Check for S3 buckets related to target"}
    options = {"max_threads": 10, "permutations": False}
    options_desc = {
        "max_threads": "Maximum number of threads for HTTP requests",
        "permutations": "Whether to try permutations",
    }
    scope_distance_modifier = 1

    cloud_helper_name = "aws"
    delimiters = ("", ".", "-")
    base_domains = ["s3.amazonaws.com"]
    regions = [None]
    supports_open_check = True

    def setup(self):
        self.buckets_tried = set()
        self.cloud_helper = getattr(self.helpers.cloud, self.cloud_helper_name)
        self.permutations = self.config.get("permutations", False)
        return True

    def filter_event(self, event):
        if event.type == "STORAGE_BUCKET":
            if f"cloud-{self.cloud_helper_name}" not in event.tags:
                return False, "Bucket belongs to a different cloud provider"
            return True
        dns_name_scope_distance = max(0, self.max_scope_distance - 2)
        if event.scope_distance <= dns_name_scope_distance:
            return True
        return False

    def handle_event(self, event):
        if event.type == "DNS_NAME":
            self.handle_dns_name(event)
        elif event.type == "STORAGE_BUCKET" and self.supports_open_check:
            self.handle_storage_bucket(event)

    def handle_dns_name(self, event):
        buckets = set()
        base = event.data
        stem = self.helpers.domain_stem(base)
        for b in [base, stem]:
            split = b.split(".")
            for d in self.delimiters:
                bucket_name = d.join(split)
                if self.valid_bucket_name(bucket_name):
                    buckets.add(bucket_name)

        if self.permutations:
            for b in [base, stem]:
                for mutation in self.helpers.word_cloud.mutations(b):
                    for d in self.delimiters:
                        bucket_name = d.join(mutation)
                        if self.valid_bucket_name(bucket_name):
                            buckets.add(bucket_name)

        futures = {}
        for base_domain in self.base_domains:
            for region in self.regions:
                for bucket_name in buckets:
                    url = self.build_url(bucket_name, base_domain, region)
                    future = self.submit_task(self.check_bucket_exists, bucket_name, url)
                    futures[future] = (bucket_name, url)
        for future in self.helpers.as_completed(futures):
            bucket_name, url = futures[future]
            existent_bucket, tags = future.result()
            if existent_bucket:
                self.emit_event({"name": bucket_name, "url": url}, "STORAGE_BUCKET", source=event, tags=tags)

    def handle_storage_bucket(self, event):
        url = event.data["url"]
        bucket_name = event.data["name"]
        description, tags = self.check_bucket_open(bucket_name, url)
        if description:
            self.emit_event(
                {"host": event.host, "url": url, "description": description}, "FINDING", source=event, tags=tags
            )

    def check_bucket_exists(self, bucket_name, url):
        response = self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        existent_bucket = status_code != 404
        return (existent_bucket, tags)

    def check_bucket_open(self, bucket_name, url):
        response = self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        content = getattr(response, "text", "")
        open_bucket = status_code == 200 and "Contents" in content
        msg = ""
        if open_bucket:
            msg = "Open storage bucket"
        return (msg, tags)

    def valid_bucket_name(self, bucket_name):
        valid = self.cloud_helper.is_valid_bucket(bucket_name)
        if valid and not self.helpers.is_ip(bucket_name):
            bucket_hash = hash(bucket_name)
            if not bucket_hash in self.buckets_tried:
                self.buckets_tried.add(bucket_hash)
                return True
        return False

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{base_domain}"

    def gen_tags_exists(self, response):
        return set()

    def gen_tags_open(self, response):
        return set()
