from .base import BaseCloudProvider


class GCP(BaseCloudProvider):
    domains = [
        "googleapis.cn",
        "googleapis.com",
        "cloud.google.com",
        "gcp.gvt2.com",
    ]

    bucket_name_regex = r"[a-z0-9][a-z0-9-_\.]{1,61}[a-z0-9]"
    regexes = {"STORAGE_BUCKET": [r"(%[a-f0-9]{2})?(" + bucket_name_regex + r")\.(storage\.googleapis\.com)"]}
