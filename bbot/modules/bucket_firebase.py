from bbot.modules.bucket_aws import bucket_aws


class bucket_firebase(bucket_aws):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic", "web-thorough"]
    meta = {"description": "Check for open Firebase databases related to target"}
    options = {"max_threads": 10, "permutations": False}
    options_desc = {
        "max_threads": "Maximum number of threads for HTTP requests",
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "firebase"
    delimiters = ("", "-")
    base_domains = ["firebaseio.com"]

    def check_bucket_exists(self, bucket_name, url):
        url = url.strip("/") + "/.json"
        return super().check_bucket_exists(bucket_name, url)

    def check_bucket_open(self, bucket_name, url):
        url = url.strip("/") + "/.json"
        response = self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        msg = ""
        if status_code == 200:
            msg = "Open storage bucket"
        return (msg, tags)
