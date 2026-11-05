import re
import yaml

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_SSL_URL, HTTPSERVER_URL

# icons are longer than 57 bytes so the newlines inserted by base64.encodebytes affect the hash
LINKED_ICON = b"\x00\x00\x01\x00\x01\x00" + bytes(range(256)) * 2
DEFAULT_ICON = b"\x00\x00\x01\x00\x02\x00" + bytes(range(255, -1, -1)) * 2
SOFT_404 = "<html><body>Not Found</body></html>"

SIGNATURES = yaml.safe_dump(
    {
        "id": "favicon-detect",
        "http": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/favicon.ico"],
                "matchers": [
                    {
                        "type": "dsl",
                        # redundant "favicon" suffixes are stripped from names
                        "name": "linked-app-favicon",
                        "dsl": ['status_code==200 && ("1059184575" == mmh3(base64_py(body)))'],
                    },
                    {
                        "type": "dsl",
                        "name": "default-app-default-favicon",
                        "dsl": ['status_code==200 && ("1852949020" == mmh3(base64_py(body)))'],
                    },
                    {
                        "type": "dsl",
                        "name": "soft-404-app",
                        "dsl": ['status_code==200 && ("-186779990" == mmh3(base64_py(body)))'],
                    },
                    {"type": "word", "name": "unparseable-app", "words": ["something"]},
                ],
            }
        ],
    }
)


class TestFavicon(ModuleTestBase):
    module_name = "favicon"
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "favicon"]
    config_overrides = {"modules": {"favicon": {"signatures_url": f"{HTTPSERVER_URL}/favicon-detect.yaml"}}}
    page = '<html><head><link rel="shortcut icon" href="/static/app.ico"></head><body>hi</body></html>'
    # (technology, page path, icon path)
    expected = {("linked-app", "/", "/static/app.ico")}

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/favicon-detect.yaml"}, {"response_data": SIGNATURES})

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": self.page, "content_type": "text/html"})
        module_test.set_expect_requests({"uri": "/static/app.ico"}, {"response_data": LINKED_ICON})
        module_test.set_expect_requests({"uri": "/favicon.ico"}, {"response_data": DEFAULT_ICON})

    def check(self, module_test, events):
        technologies = [
            (e.data["technology"], e.data["url"], re.search(r" at (\S+) to ", e.discovery_context).group(1))
            for e in events
            if e.type == "TECHNOLOGY"
        ]
        expected = {(t, f"{HTTPSERVER_URL}{page}", f"{HTTPSERVER_URL}{icon}") for t, page, icon in self.expected}
        assert sorted(technologies) == sorted(expected), f"Expected {expected}, got {technologies}"
        assert module_test.module.signatures == {
            1059184575: {"linked-app"},
            1852949020: {"default-app"},
            -186779990: {"soft-404-app"},
        }


class TestFaviconDefaultPath(TestFavicon):
    page = "<html><body>no icon declared</body></html>"
    expected = {("default-app", "/", "/favicon.ico")}


class TestFaviconSoft404(TestFavicon):
    page = "<html><body>no icon declared</body></html>"
    expected = set()

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": self.page, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/favicon.ico"}, {"response_data": SOFT_404, "content_type": "text/html"}
        )


class TestFaviconRedirect(TestFavicon):
    page = "<html><body>no icon declared</body></html>"
    expected = {("default-app", "/", "/app/favicon.ico")}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": self.page, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/favicon.ico"}, {"status": 302, "headers": {"Location": "/app/favicon.ico"}}
        )
        module_test.set_expect_requests({"uri": "/app/favicon.ico"}, {"response_data": DEFAULT_ICON})


class TestFaviconSubdirectory(TestFavicon):
    targets = [HTTPSERVER_URL, f"{HTTPSERVER_URL}/app/", f"{HTTPSERVER_URL}/same/"]
    page = "<html><body>no icon declared</body></html>"
    # /same/ serves the root's favicon, so it must not produce a second default-app

    async def setup_after_prep(self, module_test):
        for path in ("/", "/app/", "/same/"):
            module_test.set_expect_requests({"uri": path}, {"response_data": self.page, "content_type": "text/html"})
        module_test.set_expect_requests({"uri": "/favicon.ico"}, {"response_data": DEFAULT_ICON})
        module_test.set_expect_requests({"uri": "/app/favicon.ico"}, {"response_data": LINKED_ICON})
        module_test.set_expect_requests({"uri": "/same/favicon.ico"}, {"response_data": DEFAULT_ICON})

    def check(self, module_test, events):
        technologies = [e for e in events if e.type == "TECHNOLOGY"]
        assert sorted(e.data["technology"] for e in technologies) == ["default-app", "linked-app"], technologies
        # whichever of / or /same/ is processed first claims default-app
        default_app = next(e for e in technologies if e.data["technology"] == "default-app")
        assert default_app.data["url"] in (f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same/")
        linked_app = next(e for e in technologies if e.data["technology"] == "linked-app")
        assert linked_app.data["url"] == f"{HTTPSERVER_URL}/app/"
        assert f" at {HTTPSERVER_URL}/app/favicon.ico " in linked_app.discovery_context


class TestFaviconSameIconAcrossPorts(TestFavicon):
    targets = [HTTPSERVER_URL, HTTPSERVER_SSL_URL]
    page = "<html><body>no icon declared</body></html>"

    async def setup_after_prep(self, module_test):
        for server in (module_test.httpserver, module_test.httpserver_ssl):
            server.expect_request("/").respond_with_data(self.page, content_type="text/html")
            server.expect_request("/favicon.ico").respond_with_data(DEFAULT_ICON)

    def check(self, module_test, events):
        technologies = [e for e in events if e.type == "TECHNOLOGY"]
        assert len(technologies) == 1, f"Expected a single default-app event, got {technologies}"
        assert technologies[0].data["technology"] == "default-app"
        assert technologies[0].data["url"] in (f"{HTTPSERVER_URL}/", f"{HTTPSERVER_SSL_URL}/")
