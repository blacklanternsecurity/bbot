from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_cloud_helpers(bbot_scanner, bbot_config):
    scan1 = bbot_scanner("127.0.0.1", config=bbot_config)

    provider_names = ("amazon", "google", "azure", "digitalocean", "oracle", "akamai", "cloudflare", "github")
    for provider_name in provider_names:
        assert provider_name in scan1.helpers.cloud.providers.providers

    for p in scan1.helpers.cloud.providers.providers.values():
        print(f"{p.name}: {p.domains} / {p.ranges}")
    amazon_ranges = list(scan1.helpers.cloud["amazon"].ranges)
    assert amazon_ranges
    amazon_range = next(iter(amazon_ranges))
    amazon_address = amazon_range.broadcast_address

    ip_event = scan1.make_event(amazon_address, source=scan1.root_event)
    aws_event1 = scan1.make_event("amazonaws.com", source=scan1.root_event)
    aws_event2 = scan1.make_event("asdf.amazonaws.com", source=scan1.root_event)
    aws_event3 = scan1.make_event("asdfamazonaws.com", source=scan1.root_event)
    aws_event4 = scan1.make_event("test.asdf.aws", source=scan1.root_event)

    other_event1 = scan1.make_event("cname.evilcorp.com", source=scan1.root_event)
    other_event2 = scan1.make_event("cname2.evilcorp.com", source=scan1.root_event)
    other_event3 = scan1.make_event("cname3.evilcorp.com", source=scan1.root_event)
    other_event2._resolved_hosts = {amazon_address}
    other_event3._resolved_hosts = {"asdf.amazonaws.com"}

    for event in (ip_event, aws_event1, aws_event2, aws_event4, other_event2, other_event3):
        await scan1.helpers.cloud.tag_event(event)
        assert "cloud-amazon" in event.tags, f"{event} was not properly cloud-tagged"

    for event in (aws_event3, other_event1):
        await scan1.helpers.cloud.tag_event(event)
        assert "cloud-amazon" not in event.tags, f"{event} was improperly cloud-tagged"
        assert not any(
            t for t in event.tags if t.startswith("cloud-") or t.startswith("cdn-")
        ), f"{event} was improperly cloud-tagged"

    google_event1 = scan1.make_event("asdf.googleapis.com", source=scan1.root_event)
    google_event2 = scan1.make_event("asdf.google", source=scan1.root_event)
    google_event3 = scan1.make_event("asdf.evilcorp.com", source=scan1.root_event)
    google_event3._resolved_hosts = {"asdf.storage.googleapis.com"}

    for event in (google_event1, google_event2, google_event3):
        await scan1.helpers.cloud.tag_event(event)
        assert "cloud-google" in event.tags, f"{event} was not properly cloud-tagged"
    assert "cloud-storage-bucket" in google_event3.tags


@pytest.mark.asyncio
async def test_cloud_helpers_excavate(bbot_scanner, bbot_config, bbot_httpserver):
    url = bbot_httpserver.url_for("/test_cloud_helpers_excavate")
    bbot_httpserver.expect_request(uri="/test_cloud_helpers_excavate").respond_with_data(
        "<a href='asdf.s3.amazonaws.com'/>"
    )
    scan1 = bbot_scanner(url, modules=["httpx", "excavate"], config=bbot_config)
    events = [e async for e in scan1.async_start()]
    assert 1 == len(
        [
            e
            for e in events
            if e.type == "STORAGE_BUCKET"
            and e.data["name"] == "asdf"
            and "cloud-amazon" in e.tags
            and "cloud-storage-bucket" in e.tags
        ]
    )


@pytest.mark.asyncio
async def test_cloud_helpers_speculate(bbot_scanner, bbot_config):
    scan1 = bbot_scanner("asdf.s3.amazonaws.com", modules=["speculate"], config=bbot_config)
    events = [e async for e in scan1.async_start()]
    assert 1 == len(
        [
            e
            for e in events
            if e.type == "STORAGE_BUCKET"
            and e.data["name"] == "asdf"
            and "cloud-amazon" in e.tags
            and "cloud-storage-bucket" in e.tags
        ]
    )
