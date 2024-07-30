from bbot.modules.templates.bucket import bucket_template


class bucket_firebase(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for open Firebase databases related to target",
        "created_date": "2023-03-20",
        "author": "@TheTechromancer",
    }
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "google"
    delimiters = ("", "-")
    base_domains = ["firebaseio.com"]

    def filter_bucket(self, event):
        host = str(event.host)
        if not any(host.endswith(f".{d}") for d in self.base_domains):
            return False, "bucket belongs to a different cloud provider"
        return True, ""

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{base_domain}/.json"

    async def check_bucket_open(self, bucket_name, url):
        url = url.strip("/") + "/.json"
        response = await self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        msg = ""
        if status_code == 200:
            msg = "Open storage bucket"
        return (msg, tags)
