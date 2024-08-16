from bbot.modules.templates.bucket import bucket_template


class bucket_azure(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for Azure storage blobs related to target",
        "created_date": "2022-11-04",
        "author": "@TheTechromancer",
    }
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "azure"
    delimiters = ("", "-")
    base_domains = ["blob.core.windows.net"]
    # Dirbusting is required to know whether a bucket is public
    supports_open_check = False

    def build_bucket_request(self, bucket_name, base_domain, region):
        url = self.build_url(bucket_name, base_domain, region)
        url = url.strip("/") + f"/{bucket_name}?restype=container"
        return url, {}

    def check_bucket_exists(self, bucket_name, response):
        status_code = getattr(response, "status_code", 0)
        existent_bucket = status_code != 0
        return existent_bucket, set()

    def clean_bucket_url(self, url):
        # only return root URL
        return "/".join(url.split("/")[:3])
