from bbot.modules.bucket_aws import bucket_aws


class bucket_digitalocean(bucket_aws):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "slow", "cloud-enum", "web-thorough"]
    meta = {"description": "Check for DigitalOcean spaces related to target"}
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "digitalocean"
    delimiters = ("", "-")
    base_domains = ["digitaloceanspaces.com"]
    regions = ["ams3", "fra1", "nyc3", "sfo2", "sfo3", "sgp1"]

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{region}.{base_domain}"
