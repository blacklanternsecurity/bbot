from bbot.modules.bucket_aws import bucket_aws


class bucket_azure(bucket_aws):
    watched_events = ["DNS_NAME"]
    produced_events = ["STORAGE_BUCKET"]
    flags = ["active", "safe", "cloud-enum"]
    meta = {"description": "Check for Azure storage blobs related to target"}
    options = {"max_threads": 10, "permutations": False}
    options_desc = {
        "max_threads": "Maximum number of threads for HTTP requests",
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "azure"
    delimiters = ("", "-")
    base_domains = ["blob.core.windows.net"]

    def gen_tags(self, *args, **kwargs):
        return []

    def check_response(self, bucket_name, web_response):
        status_code = getattr(web_response, "status_code", 0)
        existent_bucket = status_code != 0
        event_type = "STORAGE_BUCKET"
        return existent_bucket, event_type
