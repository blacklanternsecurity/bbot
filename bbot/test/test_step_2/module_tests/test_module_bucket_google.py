from .test_module_bucket_amazon import *


class TestBucket_Google(Bucket_Amazon_Base):
    provider = "google"
    random_bucket_1 = f"{random_bucket_name_1}.storage.googleapis.com"
    random_bucket_2 = f"{random_bucket_name_2}.storage.googleapis.com"
    random_bucket_3 = f"{random_bucket_name_3}.storage.googleapis.com"
    open_bucket_body = """{
  "kind": "storage#testIamPermissionsResponse",
  "permissions": [
    "storage.objects.create",
    "storage.objects.list"
  ]
}"""

    def bucket_setup(self):
        self.url_setup()
        self.website_body = f"""
        <a href="{self.url_1}"/>
        <a href="https://{self.random_bucket_2}"/>
        """

    def url_setup(self):
        self.url_1 = f"{random_bucket_name_1}.storage.googleapis.com"
        self.url_2 = f"https://www.googleapis.com/storage/v1/b/{random_bucket_name_2}/iam/testPermissions?&permissions=storage.buckets.get&permissions=storage.buckets.list&permissions=storage.buckets.create&permissions=storage.buckets.delete&permissions=storage.buckets.setIamPolicy&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.setIamPolicy"
        self.url_3 = f"https://www.googleapis.com/storage/v1/b/{random_bucket_name_3}"
