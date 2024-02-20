from .base import ModuleTestBase


class TestGowitness(ModuleTestBase):
    targets = ["127.0.0.1:8888"]
    modules_overrides = ["gowitness", "httpx", "social", "excavate"]
    import shutil
    from pathlib import Path

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {"force_deps": True, "home": str(home_dir), "scope_report_distance": 2, "omit_event_types": []}

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
        request_args = dict(uri="/blacklanternsecurity")
        respond_args = dict(response_data="blacklanternsecurity github")
        module_test.set_expect_requests(request_args, respond_args)

        # monkeypatch social
        old_emit_event = module_test.scan.modules["social"].emit_event

        async def new_emit_event(event_data, event_type, **kwargs):
            if event_data["url"] == "https://github.com/blacklanternsecurity":
                event_data["url"] = event_data["url"].replace("https://github.com", "http://127.0.0.1:8888")
            await old_emit_event(event_data, event_type, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.modules["social"], "emit_event", new_emit_event)

    def check(self, module_test, events):
        screenshots_path = self.home_dir / "scans" / module_test.scan.name / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.png"))
        assert (
            len(screenshots) == 2
        ), f"{len(screenshots):,} .png files found at {screenshots_path}, should have been 2"
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/"])
        assert 1 == len(
            [e for e in events if e.type == "URL_UNVERIFIED" and e.data == "https://fonts.googleapis.com/"]
        )
        assert 0 == len([e for e in events if e.type == "URL" and e.data == "https://fonts.googleapis.com/"])
        assert 1 == len(
            [e for e in events if e.type == "SOCIAL" and e.data["url"] == "http://127.0.0.1:8888/blacklanternsecurity"]
        )
        assert 2 == len([e for e in events if e.type == "WEBSCREENSHOT"])
        assert 1 == len([e for e in events if e.type == "WEBSCREENSHOT" and e.data["url"] == "http://127.0.0.1:8888/"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "WEBSCREENSHOT" and e.data["url"] == "http://127.0.0.1:8888/blacklanternsecurity"
            ]
        )
        assert len([e for e in events if e.type == "TECHNOLOGY"])
