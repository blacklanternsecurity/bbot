import re
from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_PORT, HTTPSERVER_URL


class TestRobots(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "robots"]
    config_overrides = {"modules": {"robots": {"include_sitemap": True}}}

    async def setup_after_prep(self, module_test):
        sample_robots = f"Allow: /allow/\nDisallow: /disallow/\nJunk: test.com\nDisallow: /*/wildcard.txt\nSitemap: {self.targets[0]}/sitemap.txt"

        expect_args = {"method": "GET", "uri": "/robots.txt"}
        respond_args = {"response_data": sample_robots}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        allow_bool = False
        disallow_bool = False
        sitemap_bool = False
        wildcard_bool = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if str(e.module) != "SEED":
                    assert "spider-danger" in e.tags, f"{e} doesn't have spider-danger tag"
                if e.url == f"{HTTPSERVER_URL}/allow/":
                    allow_bool = True

                if e.url == f"{HTTPSERVER_URL}/disallow/":
                    disallow_bool = True

                if e.url == f"{HTTPSERVER_URL}/sitemap.txt":
                    sitemap_bool = True

                if re.match(rf"http://127\.0\.0\.1:{HTTPSERVER_PORT}/\w+/wildcard\.txt", e.url):
                    wildcard_bool = True

        assert allow_bool
        assert disallow_bool
        assert sitemap_bool
        assert wildcard_bool
