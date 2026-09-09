from bbot.modules.templates.bucket import bucket_template
from bbot.core.config.models import BaseModuleConfig, Field


class bucket_hetzner(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["safe", "active", "slow", "cloud-enum", "web-heavy"]
    meta = {
        "description": "Check for Hetzner Object Storage buckets related to target",
        "created_date": "2026-05-04",
        "author": "@ChrisJr404",
    }

    class Config(BaseModuleConfig):
        permutations: bool = Field(False, description="Whether to try permutations")

    cloudcheck_provider_name = "Hetzner"
    delimiters = ("", "-")
    base_domains = ["your-objectstorage.com"]
    # Hetzner Object Storage locations:
    #   fsn1 - Falkenstein, DE
    #   nbg1 - Nuremberg, DE
    #   hel1 - Helsinki, FI
    # https://docs.hetzner.com/storage/object-storage/overview/
    regions = ["fsn1", "nbg1", "hel1"]

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{region}.{base_domain}/"
