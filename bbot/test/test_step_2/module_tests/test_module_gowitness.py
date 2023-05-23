from .base import ModuleTestBase


class TestGowitness(ModuleTestBase):
    targets = ["127.0.0.1:8888"]
    modules_overrides = ["gowitness", "httpx"]
    import shutil
    from pathlib import Path

    home_dir = Path("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {"force_deps": True, "home": str(home_dir)}

    async def setup_after_prep(self, module_test):
        respond_args = {
            "response_data": """<html><head><title>BBOT is life</title></head><body>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans+Condensed:wght@700&family=Open+Sans:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
</body></html>""",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
        }
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        screenshots_path = self.home_dir / "scans" / module_test.scan.name / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.png"))
        assert screenshots, f"No .png files found at {screenshots_path}"
        url = False
        webscreenshot = False
        technology = False
        for event in events:
            if event.type == "URL_UNVERIFIED":
                url = True
            elif event.type == "WEBSCREENSHOT":
                webscreenshot = True
            elif event.type == "TECHNOLOGY":
                technology = True
        assert url, "No URL emitted"
        assert webscreenshot, "No WEBSCREENSHOT emitted"
        assert technology, "No TECHNOLOGY emitted"
