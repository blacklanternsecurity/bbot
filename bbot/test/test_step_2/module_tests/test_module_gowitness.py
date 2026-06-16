from pathlib import Path

from .base import ModuleTestBase


class TestGowitness(ModuleTestBase):
    targets = ["127.0.0.1:8888"]
    modules_overrides = ["gowitness", "http", "social", "excavate"]
    import shutil
    from pathlib import Path

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {
        "deps": {"behavior": "force_install"},
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
                event.parsed_url = module_test.scan.helpers.urlparse(event.data["url"])
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
        assert 1 == len([e for e in events if e.type == "URL" and e.url == "http://127.0.0.1:8888/"])
        assert 1 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.url == "https://fonts.googleapis.com/"])
        assert 0 == len([e for e in events if e.type == "URL" and e.url == "https://fonts.googleapis.com/"])
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


class TestGowitness_MultiPort(ModuleTestBase):
    """
    Integration test: two URLs on the same host with different ports
    (HTTP :8888 and HTTPS :9999) both get correctly correlated screenshots.
    Exercises the real gowitness binary and _resolve_parent tiered lookup.
    """

    targets = ["http://127.0.0.1:8888", "https://127.0.0.1:9999"]
    modules_overrides = ["gowitness", "http"]

    import shutil

    home_dir = Path("/tmp/.bbot_gowitness_multiport_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {
        "deps": {"behavior": "force_install"},
        "home": str(home_dir),
        "omit_event_types": [],
    }

    async def setup_after_prep(self, module_test):
        # HTTP server on port 8888
        module_test.set_expect_requests(
            respond_args={
                "response_data": "<html><head><title>Port 8888</title></head><body>Port 8888</body></html>",
                "headers": {"Server": "Apache/2.4.41"},
            },
        )
        # HTTPS server on port 9999
        module_test.httpserver_ssl.expect_request("/").respond_with_data(
            "<html><head><title>Port 9999</title></head><body>Port 9999</body></html>",
            headers={"Server": "nginx/1.18.0"},
        )

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert len(webscreenshots) >= 2, f"Expected at least 2 WEBSCREENSHOT events, got {len(webscreenshots)}"

        screenshot_urls = {e.data["url"] for e in webscreenshots}
        assert any("8888" in url for url in screenshot_urls), f"No screenshot for port 8888. URLs: {screenshot_urls}"
        assert any("9999" in url for url in screenshot_urls), f"No screenshot for port 9999. URLs: {screenshot_urls}"

        # Verify parent events reference the correct port
        for ws in webscreenshots:
            url = ws.data["url"]
            parent = ws.parent
            if "8888" in url:
                assert "8888" in str(parent.data), f"Screenshot for :8888 has wrong parent: {parent.data}"
            elif "9999" in url:
                assert "9999" in str(parent.data), f"Screenshot for :9999 has wrong parent: {parent.data}"
