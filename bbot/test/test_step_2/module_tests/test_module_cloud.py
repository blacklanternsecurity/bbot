from .base import ModuleTestBase


class TestCloud(ModuleTestBase):
    targets = ["www.azure.com"]

    async def setup_after_prep(self, module_test):
        scan = module_test.scan
        module = module_test.module
        providers = scan.helpers.cloud.providers
        # make sure we have all the providers
        provider_names = (
            "amazon",
            "google",
            "azure",
            "digitalocean",
            "oracle",
            "akamai",
            "cloudflare",
            "github",
            "zoho",
            "fastly",
        )
        for provider_name in provider_names:
            assert provider_name in providers

        amazon_ranges = list(providers["amazon"].ranges)
        assert amazon_ranges
        amazon_range = next(iter(amazon_ranges))
        amazon_address = amazon_range.broadcast_address

        ip_event = scan.make_event(amazon_address, source=scan.root_event)
        aws_event1 = scan.make_event("amazonaws.com", source=scan.root_event)
        aws_event2 = scan.make_event("asdf.amazonaws.com", source=scan.root_event)
        aws_event3 = scan.make_event("asdfamazonaws.com", source=scan.root_event)
        aws_event4 = scan.make_event("test.asdf.aws", source=scan.root_event)

        other_event1 = scan.make_event("cname.evilcorp.com", source=scan.root_event)
        other_event2 = scan.make_event("cname2.evilcorp.com", source=scan.root_event)
        other_event3 = scan.make_event("cname3.evilcorp.com", source=scan.root_event)
        other_event2._resolved_hosts = {amazon_address}
        other_event3._resolved_hosts = {"asdf.amazonaws.com"}

        for event in (ip_event, aws_event1, aws_event2, aws_event4, other_event2, other_event3):
            await module.handle_event(event, {})
            assert "cloud-amazon" in event.tags, f"{event} was not properly cloud-tagged"

        for event in (aws_event3, other_event1):
            await module.handle_event(event, {})
            assert "cloud-amazon" not in event.tags, f"{event} was improperly cloud-tagged"
            assert not any(
                t for t in event.tags if t.startswith("cloud-") or t.startswith("cdn-")
            ), f"{event} was improperly cloud-tagged"

        google_event1 = scan.make_event("asdf.googleapis.com", source=scan.root_event)
        google_event2 = scan.make_event("asdf.google", source=scan.root_event)
        google_event3 = scan.make_event("asdf.evilcorp.com", source=scan.root_event)
        google_event3._resolved_hosts = {"asdf.storage.googleapis.com"}

        for event in (google_event1, google_event2, google_event3):
            await module.handle_event(event, {})
            assert "cloud-google" in event.tags, f"{event} was not properly cloud-tagged"
        assert "cloud-storage-bucket" in google_event3.tags

    def check(self, events, module_test):
        pass


# @pytest.mark.asyncio
# async def test_cloud_helpers_excavate(bbot_scanner, bbot_httpserver):
#     url = bbot_httpserver.url_for("/test_cloud_helpers_excavate")
#     bbot_httpserver.expect_request(uri="/test_cloud_helpers_excavate").respond_with_data(
#         "<a href='asdf.s3.amazonaws.com'/>"
#     )
#     scan = bbot_scanner(url, modules=["httpx"], config={"excavate": True})
#     events = [e async for e in scan.async_start()]
#     assert 1 == len(
#         [
#             e
#             for e in events
#             if e.type == "STORAGE_BUCKET"
#             and e.data["name"] == "asdf"
#             and "cloud-amazon" in e.tags
#             and "cloud-storage-bucket" in e.tags
#         ]
#     )


# @pytest.mark.asyncio
# async def test_cloud_helpers_speculate(bbot_scanner):
#     scan = bbot_scanner("asdf.s3.amazonaws.com", config={"speculate": True})
#     events = [e async for e in scan.async_start()]
#     assert 1 == len(
#         [
#             e
#             for e in events
#             if e.type == "STORAGE_BUCKET"
#             and e.data["name"] == "asdf"
#             and "cloud-amazon" in e.tags
#             and "cloud-storage-bucket" in e.tags
#         ]
#     )
