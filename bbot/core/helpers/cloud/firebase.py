from .base import BaseCloudProvider


class Firebase(BaseCloudProvider):
    domains = [
        "firebaseio.com",
    ]

    bucket_name_regex = r"[a-z0-9][a-z0-9-_\.]{1,61}[a-z0-9]"
    regexes = {"STORAGE_BUCKET": [r"(" + bucket_name_regex + r")\.(firebaseio\.com)"]}
