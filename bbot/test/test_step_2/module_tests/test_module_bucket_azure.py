from .test_module_bucket_amazon import *
from .base import ModuleTestBase


class TestBucket_Azure(Bucket_Amazon_Base):
    provider = "azure"
    random_bucket_1 = f"{random_bucket_name_1}.blob.core.windows.net"
    random_bucket_2 = f"{random_bucket_name_2}.blob.core.windows.net"
    random_bucket_3 = f"{random_bucket_name_3}.blob.core.windows.net"

    def url_setup(self):
        self.url_1 = f"https://{self.random_bucket_1}"
        self.url_2 = f"https://{self.random_bucket_2}"
        self.url_3 = f"https://{self.random_bucket_3}/{random_bucket_name_3}?restype=container"


class TestBucket_Azure_NoDup(ModuleTestBase):
    targets = ["tesla.com"]
    module_name = "bucket_azure"
    config_overrides = {"cloudcheck": True}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://tesla.blob.core.windows.net/tesla?restype=container",
            text="",
        )
        await module_test.mock_dns(
            {
                "tesla.com": {"A": ["1.2.3.4"]},
                "tesla.blob.core.windows.net": {"A": ["1.2.3.4"]},
            }
        )

    def check(self, module_test, events):
        assert 1 == len([e for e in events if e.type == "STORAGE_BUCKET"])
        bucket_event = [e for e in events if e.type == "STORAGE_BUCKET"][0]
        assert bucket_event.data["name"] == "tesla"
        assert bucket_event.data["url"] == "https://tesla.blob.core.windows.net/"
        assert (
            bucket_event.discovery_context
            == f"bucket_azure tried  bucket variations of {event.data} and found {{event.type}} at {url}"
        )


class TestBucket_Azure_NoDup(TestBucket_Azure_NoDup):
    """
    This tests _suppress_chain_dupes functionality to make sure it works as expected
    """

    async def setup_after_prep(self, module_test):
        from bbot.core.event.base import STORAGE_BUCKET

        module_test.monkeypatch.setattr(STORAGE_BUCKET, "_suppress_chain_dupes", False)

    def check(self, module_test, events):
        assert 2 == len([e for e in events if e.type == "STORAGE_BUCKET"])
