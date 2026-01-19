from .base import ModuleTestBase

from bbot.scanner import Scanner


class TestCloudCheck(ModuleTestBase):
    targets = ["http://127.0.0.1:8888", "asdf2.storage.googleapis.com"]
    modules_overrides = ["httpx", "excavate", "cloudcheck"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": "<a href='http://asdf.s3.amazonaws.com'/>"})

        scan = Scanner(config={"cloudcheck": True})
        await scan._prep()
        module = scan.modules["cloudcheck"]
        from cloudcheck import providers

        # make sure we have at least one provider
        assert providers.Amazon.name == "Amazon"

        ip_event = scan.make_event("8.8.8.8", parent=scan.root_event)
        aws_event1 = scan.make_event("amazonaws.com", parent=scan.root_event)
        aws_event2 = scan.make_event("asdf.amazonaws.com", parent=scan.root_event)
        aws_event3 = scan.make_event("asdfamazonaws.com", parent=scan.root_event)
        aws_event4 = scan.make_event("test.asdf.aws", parent=scan.root_event)

        other_event1 = scan.make_event("cname.evilcorp.com", parent=scan.root_event)
        other_event2 = scan.make_event("cname2.evilcorp.com", parent=scan.root_event)
        other_event3 = scan.make_event("cname3.evilcorp.com", parent=scan.root_event)
        other_event2._resolved_hosts = {"8.8.8.8"}
        other_event3._resolved_hosts = {"asdf.amazonaws.com"}

        for event in (ip_event, other_event2):
            await module.handle_event(ip_event)
            assert "cloud-google" in ip_event.tags
            assert "google-ip" in ip_event.tags

        for event in (aws_event1, aws_event2, aws_event4, other_event3):
            await module.handle_event(event)
            assert "cloud-amazon" in event.tags, f"{event} was not properly cloud-tagged"

        assert "amazon-domain" in aws_event1.tags
        assert "amazon-cname" in other_event3.tags

        for event in (aws_event3, other_event1):
            await module.handle_event(event)
            assert "cloud-amazon" not in event.tags, f"{event} was improperly cloud-tagged"
            assert not any(t for t in event.tags if t.startswith("cloud-") or t.startswith("cdn-")), (
                f"{event} was improperly cloud-tagged"
            )

        google_event1 = scan.make_event("asdf.googleapis.com", parent=scan.root_event)
        google_event2 = scan.make_event("asdf.google", parent=scan.root_event)
        google_event3 = scan.make_event("asdf.evilcorp.com", parent=scan.root_event)
        google_event3._resolved_hosts = {"asdf.storage.googleapis.com"}

        for event in (google_event1, google_event2, google_event3):
            await module.handle_event(event)
            assert "cloud-google" in event.tags, f"{event} was not properly cloud-tagged"

        await scan._cleanup()

    def check(self, module_test, events):
        assert 2 == len([e for e in events if e.type == "STORAGE_BUCKET"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "STORAGE_BUCKET"
                and e.data["name"] == "asdf"
                and str(e.module) == "cloudcheck"
                and "cloud-amazon" in e.tags
                and "amazon-domain" in e.tags
                and e.scope_distance == 1
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "STORAGE_BUCKET"
                and e.data["name"] == "asdf2"
                and str(e.module) == "cloudcheck"
                and "cloud-google" in e.tags
                and "google-domain" in e.tags
                and e.scope_distance == 0
            ]
        )
