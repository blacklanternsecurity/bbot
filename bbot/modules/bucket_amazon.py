from bbot.modules.templates.bucket import bucket_template


class bucket_amazon(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for S3 buckets related to target",
        "created_date": "2022-11-04",
        "author": "@TheTechromancer",
    }
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }
    scope_distance_modifier = 3

    cloud_helper_name = "amazon"
    delimiters = ("", ".", "-")
    base_domains = ["s3.amazonaws.com"]
    regions = [None]
    supports_open_check = True
