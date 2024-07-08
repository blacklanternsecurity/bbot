from bbot.modules.templates.bucket import bucket_template


class bucket_google(bucket_template):
    """
    Adapted from https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py
    """

    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for Google object storage related to target",
        "created_date": "2022-11-04",
        "author": "@TheTechromancer",
    }
    options = {"permutations": False}
    options_desc = {
        "permutations": "Whether to try permutations",
    }

    cloud_helper_name = "google"
    delimiters = ("", "-", ".", "_")
    base_domains = ["storage.googleapis.com"]
    bad_permissions = [
        "storage.buckets.get",
        "storage.buckets.list",
        "storage.buckets.create",
        "storage.buckets.delete",
        "storage.buckets.setIamPolicy",
        "storage.objects.get",
        "storage.objects.list",
        "storage.objects.create",
        "storage.objects.delete",
        "storage.objects.setIamPolicy",
    ]

    def filter_bucket(self, event):
        if not str(event.host).endswith(".googleapis.com"):
            return False, "bucket belongs to a different cloud provider"
        return True, ""

    def build_url(self, bucket_name, base_domain, region):
        return f"https://www.googleapis.com/storage/v1/b/{bucket_name}"

    async def check_bucket_open(self, bucket_name, url):
        bad_permissions = []
        try:
            list_permissions = "&".join(["=".join(("permissions", p)) for p in self.bad_permissions])
            url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}/iam/testPermissions?" + list_permissions
            response = await self.helpers.request(url)
            permissions = response.json()
            if isinstance(permissions, dict):
                bad_permissions = list(permissions.get("permissions", {}))
        except Exception as e:
            self.info(f'Failed to enumerate permissions for bucket "{bucket_name}": {e}')
        msg = ""
        if bad_permissions:
            perms_str = ",".join(bad_permissions)
            msg = f"Open permissions on storage bucket ({perms_str})"
        return (msg, set())

    def check_bucket_exists(self, bucket_name, response):
        status_code = getattr(response, "status_code", 0)
        existent_bucket = status_code not in (0, 400, 404)
        return existent_bucket, set()
