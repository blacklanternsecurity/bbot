from .test_module_bucket_amazon import *


class TestBucket_Hetzner(Bucket_Amazon_Base):
    provider = "hetzner"
    random_bucket_1 = f"{random_bucket_name_1}.fsn1.your-objectstorage.com"
    random_bucket_2 = f"{random_bucket_name_2}.nbg1.your-objectstorage.com"
    random_bucket_3 = f"{random_bucket_name_3}.fsn1.your-objectstorage.com"
