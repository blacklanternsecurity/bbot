from .test_module_bucket_amazon import *


class TestBucket_DigitalOcean(Bucket_Amazon_Base):
    provider = "digitalocean"
    random_bucket_1 = f"{random_bucket_name_1}.fra1.digitaloceanspaces.com"
    random_bucket_2 = f"{random_bucket_name_2}.fra1.digitaloceanspaces.com"
    random_bucket_3 = f"{random_bucket_name_3}.fra1.digitaloceanspaces.com"

    open_bucket_body = """<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>cloud01</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>test.doc</Key><LastModified>2020-10-14T15:23:37.545Z</LastModified><ETag>&quot;4d25c8699f7347acc9f41e57148c62c0&quot;</ETag><Size>13362425</Size><StorageClass>STANDARD</StorageClass><Owner><ID>1957883</ID><DisplayName>1957883</DisplayName></Owner><Type>Normal</Type></Contents><Marker></Marker></ListBucketResult>"""
