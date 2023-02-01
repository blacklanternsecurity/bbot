from ..bbot_fixtures import *  # noqa: F401


def test_cloud_helpers(monkeypatch, bbot_scanner, bbot_config):
    scan1 = bbot_scanner("127.0.0.1", config=bbot_config)
    scan1.load_modules()
    aws_event1 = scan1.make_event("amazonaws.com", source=scan1.root_event)
    aws_event2 = scan1.make_event("asdf.amazonaws.com", source=scan1.root_event)
    aws_event3 = scan1.make_event("asdfamazonaws.com", source=scan1.root_event)
    providers = scan1.helpers.cloud.providers

    # make sure they're all here
    assert "aws" in providers
    assert "gcp" in providers
    assert "azure" in providers
    assert "digitalocean" in providers

    # make sure tagging is working
    aws = providers["aws"]
    aws.tag_event(aws_event1)
    assert "cloud-aws" in aws_event1.tags
    aws.tag_event(aws_event2)
    assert "cloud-aws" in aws_event2.tags
    aws.tag_event(aws_event3)
    assert not "cloud-aws" in aws_event3.tags

    # test storage bucket extraction
    storage_bucket_hosts = [
        "asdf.s3-asdf.amazonaws.com",
        "asdf.storage.googleapis.com",
        "asdf.blob.core.windows.net",
        "asdf.digitaloceanspaces.com",
    ]
    dummy_body = ""
    for h in storage_bucket_hosts:
        dummy_body += f'<a src="https://{h}"/>'
    dummy_response = {"body": dummy_body, "url": "http://example.com"}
    http_response = scan1.make_event(dummy_response, "HTTP_RESPONSE", source=scan1.root_event)
    results = []
    for provider_name, provider in providers.items():
        monkeypatch.setattr(
            provider,
            "emit_event",
            lambda *args, **kwargs: results.append(kwargs.get("data", {}).get("url", "")),
        )
        provider.excavate(http_response)
    for h in storage_bucket_hosts:
        assert f"https://{h}" in results, f"cloud helpers failed to excavate {h} from {dummy_body}"
