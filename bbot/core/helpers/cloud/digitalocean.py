from .base import BaseCloudProvider


class DigitalOcean(BaseCloudProvider):
    domains = [
        "digitaloceanspaces.com",
    ]

    bucket_name_regex = r"[a-z0-9][a-z0-9-]{2,62}"
    regexes = {"STORAGE_BUCKET": [r"(" + bucket_name_regex + r")\.([a-z]{3}[\d]{1}\.digitaloceanspaces\.com)"]}
