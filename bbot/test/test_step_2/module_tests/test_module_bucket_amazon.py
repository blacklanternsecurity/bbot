import re

from .base import ModuleTestBase
from bbot.core.helpers.misc import rand_string

__all__ = ["random_bucket_name_1", "random_bucket_name_2", "random_bucket_name_3", "Bucket_Amazon_Base"]

# first one is a normal bucket
random_bucket_name_1 = rand_string(15, digits=False)
# second one is open/vulnerable
random_bucket_name_2 = rand_string(15, digits=False)
# third one is a mutation
random_bucket_name_3 = f"{random_bucket_name_2}-dev"


class Bucket_Amazon_Base(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    provider = "amazon"

    random_bucket_1 = f"{random_bucket_name_1}.s3.amazonaws.com"
    random_bucket_2 = f"{random_bucket_name_2}.s3-ap-southeast-2.amazonaws.com"
    random_bucket_3 = f"{random_bucket_name_3}.s3.amazonaws.com"

    open_bucket_body = """<?xml version="1.0" encoding="UTF-8"?>
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>vpn-static</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>style.css</Key><LastModified>2017-03-18T06:41:59.000Z</LastModified><ETag>&quot;bf9e72bdab09b785f05ff0395023cc35&quot;</ETag><Size>429</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"""

    @property
    def config_overrides(self):
        return {"modules": {self.module_name: {"permutations": True}}}

    @property
    def module_name(self):
        return self.__class__.__name__.lower().split("test")[-1]

    @property
    def modules_overrides(self):
        return ["excavate", "speculate", "httpx", self.module_name, "cloudcheck"]

    def url_setup(self):
        self.url_1 = f"https://{self.random_bucket_1}/"
        self.url_2 = f"https://{self.random_bucket_2}/"
        self.url_3 = f"https://{self.random_bucket_3}/"

    def bucket_setup(self):
        self.url_setup()
        self.website_body = f"""
        <a href="{self.url_1}"/>
        <a href="{self.url_2}"/>
        """

    async def setup_after_prep(self, module_test):
        self.bucket_setup()
        # patch mutations
        module_test.scan.helpers.word_cloud.mutations = lambda b, cloud=False: [
            (b, "dev"),
        ]
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"}, respond_args={"response_data": self.website_body}
        )
        if module_test.module.supports_open_check:
            module_test.httpx_mock.add_response(
                url=self.url_2,
                text=self.open_bucket_body,
            )
        module_test.httpx_mock.add_response(
            url=self.url_3,
            text="",
        )
        module_test.httpx_mock.add_response(url=re.compile(".*"), text="", status_code=404)

    def check(self, module_test, events):
        # make sure buckets were excavated
        assert any(
            e.type == "STORAGE_BUCKET" and str(e.module) == f"cloud_{self.provider}" for e in events
        ), f'bucket not found for module "{self.module_name}"'
        # make sure open buckets were found
        if module_test.module.supports_open_check:
            assert any(
                e.type == "FINDING" and str(e.module) == self.module_name for e in events
            ), f'open bucket not found for module "{self.module_name}"'
            for e in events:
                if e.type == "FINDING" and str(e.module) == self.module_name:
                    url = e.data.get("url", "")
                    assert self.random_bucket_2 in url
                    assert not self.random_bucket_1 in url
                    assert not self.random_bucket_3 in url
        # make sure bucket mutations were found
        assert any(
            e.type == "STORAGE_BUCKET"
            and str(e.module) == self.module_name
            and f"{random_bucket_name_3}" in e.data["url"]
            for e in events
        ), f'bucket (dev mutation: {self.random_bucket_3}) not found for module "{self.module_name}"'


class TestBucket_Amazon(Bucket_Amazon_Base):
    pass
