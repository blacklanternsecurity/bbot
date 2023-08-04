from .test_module_bucket_aws import *


class TestBucket_Azure(Bucket_AWS_Base):
    provider = "azure"
    random_bucket_1 = f"{random_bucket_name_1}.blob.core.windows.net"
    random_bucket_2 = f"{random_bucket_name_2}.blob.core.windows.net"
    random_bucket_3 = f"{random_bucket_name_3}.blob.core.windows.net"

    def url_setup(self):
        self.url_1 = f"https://{self.random_bucket_1}"
        self.url_2 = f"https://{self.random_bucket_2}"
        self.url_3 = f"https://{self.random_bucket_3}/{random_bucket_name_3}?restype=container"
