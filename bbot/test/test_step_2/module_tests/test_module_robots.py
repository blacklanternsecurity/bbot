import re
from .base import ModuleTestBase


class TestRobots(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "robots"]
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
                if str(e.module) != "TARGET":
                    assert "spider-danger" in e.tags, f"{e} doesn't have spider-danger tag"
                if e.data == "http://127.0.0.1:8888/allow/":
                    allow_bool = True

                if e.data == "http://127.0.0.1:8888/disallow/":
                    disallow_bool = True

                if e.data == "http://127.0.0.1:8888/sitemap.txt":
                    sitemap_bool = True

                if re.match(r"http://127\.0\.0\.1:8888/\w+/wildcard\.txt", e.data):
                    wildcard_bool = True

        assert allow_bool
        assert disallow_bool
        assert sitemap_bool
        assert wildcard_bool
