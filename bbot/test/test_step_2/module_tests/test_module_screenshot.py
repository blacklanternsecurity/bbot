import hashlib

import pytest

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL

PAGE = "<html><head><title>screenshot test</title></head><body><h1>{}</h1></body></html>"


class TestScreenshot(ModuleTestBase):
    pytestmark = pytest.mark.browser
    # two URLs serving the same page, and one that differs
    targets = [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/different"]
    modules_overrides = ["http", "screenshot"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        same = PAGE.format("the same page")
        module_test.set_expect_requests({"uri": "/"}, {"response_data": same, "content_type": "text/html"})
        module_test.set_expect_requests({"uri": "/same"}, {"response_data": same, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/different"}, {"response_data": PAGE.format("a different page"), "content_type": "text/html"}
        )

    def check(self, module_test, events):
        screenshots = {e.data["url"]: e for e in events if e.type == "WEBSCREENSHOT"}
        assert set(screenshots) == {f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/different"}

        for event in screenshots.values():
            data = event.data
            path = module_test.scan.home / data["path"]
            png = path.read_bytes()
            assert png.startswith(b"\x89PNG")
            # stored under its content hash, and described by it
            assert path.name == f"{data['sha256']}.png"
            assert data["sha256"] == hashlib.sha256(png).hexdigest()
            assert data["size"] == len(png)
            assert data["mime_type"] == "image/png"
            assert data["width"] > 0 and data["height"] > 0
            assert len(data["dhash"]) == 16
            assert "file" in event.tags

        # identical pages are one file
        same, also_same, different = (
            screenshots[f"{HTTPSERVER_URL}/"],
            screenshots[f"{HTTPSERVER_URL}/same"],
            screenshots[f"{HTTPSERVER_URL}/different"],
        )
        assert same.data["path"] == also_same.data["path"]
        assert same.data["path"] != different.data["path"]
        assert len(list((module_test.scan.home / "screenshots").iterdir())) == 2
