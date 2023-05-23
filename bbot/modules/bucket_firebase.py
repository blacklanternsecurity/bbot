from bbot.modules.bucket_aws import bucket_aws


class bucket_firebase(bucket_aws):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic", "web-thorough"]
    meta = {"description": "Check for open Firebase databases related to target"}
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "firebase"
    delimiters = ("", "-")
    base_domains = ["firebaseio.com"]

    async def check_bucket_exists(self, bucket_name, url):
        url = url.strip("/") + "/.json"
        return await super().check_bucket_exists(bucket_name, url)

    async def check_bucket_open(self, bucket_name, url):
        url = url.strip("/") + "/.json"
        response = await self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        msg = ""
        if status_code == 200:
            msg = "Open storage bucket"
        return (msg, tags)
