from pathlib import Path

from .base import ModuleTestBase


class TestGowitness(ModuleTestBase):
    targets = ["127.0.0.1:8888"]
    modules_overrides = ["gowitness", "httpx", "social", "excavate"]
    import shutil
    from pathlib import Path

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {
        "force_deps": True,
        "home": str(home_dir),
        "scope": {"report_distance": 2},
        "omit_event_types": [],
    }

    async def setup_after_prep(self, module_test):
        respond_args = {
            "response_data": """<html><head><title>BBOT is life</title></head><body>
<link href="https://github.com/blacklanternsecurity">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans+Condensed:wght@700&family=Open+Sans:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
</body></html>""",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
        }
        module_test.set_expect_requests(respond_args=respond_args)
        request_args = {"uri": "/blacklanternsecurity"}
        respond_args = {"response_data": """blacklanternsecurity github <a data-bem"""}
        module_test.set_expect_requests(request_args, respond_args)

        # monkeypatch social
        old_emit_event = module_test.scan.modules["social"].emit_event

        async def new_emit_event(event, **kwargs):
            if event.data["url"] == "https://github.com/blacklanternsecurity":
                event.data["url"] = event.data["url"].replace("https://github.com", "http://127.0.0.1:8888")
            await old_emit_event(event, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.modules["social"], "emit_event", new_emit_event)

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert webscreenshots, "failed to raise WEBSCREENSHOT events"
        assert not any("blob" in e.data for e in webscreenshots), (
            "blob was included in WEBSCREENSHOT data when it shouldn't have been"
        )

        screenshots_path = self.home_dir / "scans" / module_test.scan.name / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.jpeg"))
        assert len(screenshots) == 1, (
            f"{len(screenshots):,} .jpeg files found at {screenshots_path}, should have been 1"
        )
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/"])
        assert 1 == len(
            [e for e in events if e.type == "URL_UNVERIFIED" and e.data == "https://fonts.googleapis.com/"]
        )
        assert 0 == len([e for e in events if e.type == "URL" and e.data == "https://fonts.googleapis.com/"])
        assert 1 == len(
            [e for e in events if e.type == "SOCIAL" and e.data["url"] == "http://127.0.0.1:8888/blacklanternsecurity"]
        )
        assert 1 == len([e for e in events if e.type == "WEBSCREENSHOT"])
        assert 1 == len([e for e in events if e.type == "WEBSCREENSHOT" and e.data["url"] == "http://127.0.0.1:8888/"])
        assert len([e for e in events if e.type == "TECHNOLOGY"])


class TestGowitness_Social(TestGowitness):
    config_overrides = dict(TestGowitness.config_overrides)
    config_overrides.update({"modules": {"gowitness": {"social": True}}})

    def check(self, module_test, events):
        screenshots_path = self.home_dir / "scans" / module_test.scan.name / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.jpeg"))
        assert len(screenshots) == 2, (
            f"{len(screenshots):,} .jpeg files found at {screenshots_path}, should have been 2"
        )
        assert 2 == len([e for e in events if e.type == "WEBSCREENSHOT"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "WEBSCREENSHOT" and e.data["url"] == "http://127.0.0.1:8888/blacklanternsecurity"
            ]
        )
        assert len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY"
                and e.data["url"] == "http://127.0.0.1:8888/blacklanternsecurity"
                and e.parent.type == "SOCIAL"
            ]
        )


class TestGoWitnessWithBlob(TestGowitness):
    config_overrides = {"file_blobs": True}

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert webscreenshots, "failed to raise WEBSCREENSHOT events"
        assert all("blob" in e.data and e.data["blob"] for e in webscreenshots), "blob not found in WEBSCREENSHOT data"


class TestGoWitnessLongFilename(TestGowitness):
    """
    Make sure long filenames are truncated properly
    """

    targets = [
        "http://127.0.0.1:8888/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity"
    ]
    config_overrides = {"file_blobs": True}

    async def setup_after_prep(self, module_test):
        request_args = {
            "uri": "/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity"
        }
        respond_args = {
            "response_data": "<html><head><title>BBOT is life</title></head><body>BBOT is life</body></html>",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
        }
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert webscreenshots, "failed to raise WEBSCREENSHOT events"
        assert len(webscreenshots) == 1
        webscreenshot = webscreenshots[0]
        filename = Path(webscreenshot.data["path"])
        # sadly this file doesn't exist because gowitness doesn't truncate properly
        assert not filename.exists()


class TestGowitness_ResolveParent(ModuleTestBase):
    """
    Test the _resolve_parent tiered lookup logic that correlates gowitness
    DB URLs back to input events. Validates both exact match and loose
    (hostname+path) fallback without needing gowitness/Chrome to run.
    """

    targets = ["127.0.0.1:8888"]
    modules_overrides = ["gowitness", "httpx"]

    import shutil

    home_dir = Path("/tmp/.bbot_gowitness_resolve_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {
        "force_deps": True,
        "home": str(home_dir),
        "omit_event_types": [],
    }

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            respond_args={"response_data": "<html><head><title>Test</title></head><body>Test</body></html>"},
        )

    def check(self, module_test, events):
        gw = module_test.scan.modules["gowitness"]

        # Simulate events with different schemes/ports
        class FakeEvent:
            def __init__(self, url):
                self.data = url
                self.type = "URL"

        event_http = FakeEvent("http://example.com/")
        event_https = FakeEvent("https://example.com/")
        event_8080 = FakeEvent("http://example.com:8080/path")

        # Build dicts as handle_batch would
        gw._event_dict = {}
        gw._event_dict_loose = {}
        for e in [event_http, event_https, event_8080]:
            gw._event_dict[e.data] = e
            loose_key = gw._url_key(gw.helpers.urlparse(e.data))
            gw._event_dict_loose.setdefault(loose_key, e)

        # Exact match works
        assert gw._resolve_parent("http://example.com/") is event_http
        assert gw._resolve_parent("https://example.com/") is event_https
        assert gw._resolve_parent("http://example.com:8080/path") is event_8080

        # Loose fallback: gowitness records http://host:443/ for https://host/
        # Loose key "example.com/" maps to event_http (first via setdefault)
        assert gw._resolve_parent("http://example.com:443/") is event_http

        # Different path resolves via loose fallback
        assert gw._resolve_parent("https://example.com:9999/path") is event_8080

        # Unknown URL returns None
        assert gw._resolve_parent("http://unknown.com/") is None
