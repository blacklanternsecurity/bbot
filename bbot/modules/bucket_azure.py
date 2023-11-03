from bbot.modules.templates.bucket import bucket_template


class bucket_azure(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic", "web-thorough"]
    meta = {"description": "Check for Azure storage blobs related to target"}
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "azure"
    delimiters = ("", "-")
    base_domains = ["blob.core.windows.net"]
    # Dirbusting is required to know whether a bucket is public
    supports_open_check = False

    async def check_bucket_exists(self, bucket_name, url):
        url = url.strip("/") + f"/{bucket_name}?restype=container"
        response = await self.helpers.request(url, retries=0)
        status_code = getattr(response, "status_code", 0)
        existent_bucket = status_code != 0
        return existent_bucket, set(), bucket_name, url
