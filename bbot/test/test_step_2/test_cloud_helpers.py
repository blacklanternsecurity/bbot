from ..bbot_fixtures import *  # noqa: F401


@pytest.mark.asyncio
async def test_cloud_helpers(monkeypatch, bbot_scanner, bbot_config):
    scan1 = bbot_scanner("127.0.0.1", config=bbot_config)
    await scan1.load_modules()
    aws_event1 = scan1.make_event("amazonaws.com", source=scan1.root_event)
    aws_event2 = scan1.make_event("asdf.amazonaws.com", source=scan1.root_event)
    aws_event3 = scan1.make_event("asdfamazonaws.com", source=scan1.root_event)
    providers = scan1.helpers.cloud.providers

    provider_names = ("aws", "gcp", "azure", "firebase", "digitalocean")

    # make sure they're all here
    for name in provider_names:
        assert name in providers

    # make sure tagging is working
    aws = providers["aws"]
    aws.tag_event(aws_event1)
    assert "cloud-aws" in aws_event1.tags
    aws.tag_event(aws_event2)
    assert "cloud-aws" in aws_event2.tags
    aws.tag_event(aws_event3)
    assert "cloud-aws" not in aws_event3.tags
