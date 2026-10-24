import hashlib

import pytest

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL

PAGE = "<html><head><title>screenshot test</title></head><body><h1>{}</h1></body></html>"


class TestScreenshot(ModuleTestBase):
    pytestmark = pytest.mark.browser
    # two URLs serving the same page, one that differs, and two that aren't pages
    targets = [
        f"{HTTPSERVER_URL}/",
        f"{HTTPSERVER_URL}/same",
        f"{HTTPSERVER_URL}/different",
        f"{HTTPSERVER_URL}/photo",
        f"{HTTPSERVER_URL}/data",
    ]
    modules_overrides = ["http", "screenshot"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        same = PAGE.format("the same page")
        module_test.set_expect_requests({"uri": "/"}, {"response_data": same, "content_type": "text/html"})
        module_test.set_expect_requests({"uri": "/same"}, {"response_data": same, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/different"}, {"response_data": PAGE.format("a different page"), "content_type": "text/html"}
        )
        module_test.set_expect_requests({"uri": "/photo"}, {"response_data": b"\x89PNG", "content_type": "image/png"})
        module_test.set_expect_requests(
            {"uri": "/data"}, {"response_data": '{"a": 1}', "content_type": "application/json; charset=utf-8"}
        )

    def check(self, module_test, events):
        screenshots = {e.data["url"]: e for e in events if e.type == "WEBSCREENSHOT"}
        assert set(screenshots) == {f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/different"}

        # an image or JSON isn't a page: the http module visits it, the browser never does
        urls = {e.url: e for e in events if e.type == "URL"}
        assert urls[f"{HTTPSERVER_URL}/photo"].content_type == "image/png"
        assert urls[f"{HTTPSERVER_URL}/data"].content_type == "application/json"
        for path in ("/photo", "/data"):
            assert len([r for r, _ in module_test.httpserver.log if r.path == path]) == 1

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


class TestScreenshotJsRedirect(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/leaving"]
    # without browser_dom, the destination of a redirect the browser held is still emitted
    modules_overrides = ["http", "screenshot"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        leaving = "<html><body><h1>leaving</h1><script>location.href = '/destination';</script></body></html>"
        module_test.set_expect_requests({"uri": "/leaving"}, {"response_data": leaving, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/destination"}, {"response_data": "<html>destination</html>", "content_type": "text/html"}
        )

    def check(self, module_test, events):
        screenshots = {e.data["url"] for e in events if e.type == "WEBSCREENSHOT"}
        # the page that redirected is captured as itself, and the destination gets its own screenshot
        assert screenshots == {f"{HTTPSERVER_URL}/leaving", f"{HTTPSERVER_URL}/destination"}
        destinations = [e for e in events if e.type == "URL_UNVERIFIED" and "js-redirect" in e.tags]
        assert [e.url for e in destinations] == [f"{HTTPSERVER_URL}/destination"]
        assert str(destinations[0].module) == "screenshot"
