from .test_module_bucket_amazon import *


class TestBucket_Firebase(Bucket_Amazon_Base):
    provider = "google"
    random_bucket_1 = f"{random_bucket_name_1}.firebaseio.com"
    random_bucket_2 = f"{random_bucket_name_2}.firebaseio.com"
    random_bucket_3 = f"{random_bucket_name_3}.firebaseio.com"

    def url_setup(self):
        self.url_1 = f"https://{self.random_bucket_1}"
        self.url_2 = f"https://{self.random_bucket_2}/.json"
        self.url_3 = f"https://{self.random_bucket_3}/.json"
