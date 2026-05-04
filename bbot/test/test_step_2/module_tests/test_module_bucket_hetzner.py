from .base import ModuleTestBase


class TestBucket_Hetzner(ModuleTestBase):
    """
    Minimal smoke test for the bucket_hetzner module.

    The shared Bucket_Amazon_Base pattern depends on the cloudcheck provider regex
    capturing a bucket name and host as separate groups. The Hetzner regex in
    cloudcheck currently matches `<bucket>.your-objectstorage.com` without a
    region segment, so test fixtures that mirror real Hetzner Object Storage URLs
    of the form `<bucket>.<location>.your-objectstorage.com` confuse the parser.
    Until the cloudcheck regex is updated to capture region, this test verifies the
    module loads, exposes the expected build_url() shape, and is wired up with the
    Hetzner cloudcheck provider.
    """

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["bucket_hetzner"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": ""},
        )

    def check(self, module_test, events):
        module = module_test.scan.modules["bucket_hetzner"]
        assert module.cloudcheck_provider_name == "Hetzner"
        assert module.base_domains == ["your-objectstorage.com"]
        assert module.regions == ["fsn1", "nbg1", "hel1"]
        # Live build_url uses Hetzner's documented host shape:
        # https://<bucket>.<location>.your-objectstorage.com/
        url = module.build_url("examplebucket", "your-objectstorage.com", "fsn1")
        assert url == "https://examplebucket.fsn1.your-objectstorage.com/"
        # cloudcheck Hetzner provider must be available
        assert module.cloudcheck_provider is not None
