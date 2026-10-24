import pytest

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL

# the API call and the link only exist once the script runs (neither path is even in the source), so only a real
# browser sees them
PAGE = """<html><head><title>browser dom test</title></head><body>
<img src="/pixel.png">
<script>
fetch("/api/" + "data");
const link = document.createElement("a");
link.href = "/js-" + "built-link";
document.body.appendChild(link);
</script>
</body></html>"""


class TestBrowserDom(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "browser_dom"]
    config_overrides = {"web": {"enable_browser": True, "spider_distance": 1, "spider_depth": 2}, "excavate": True}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": PAGE, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/api/data"},
            {"response_data": '{"api_marker": "seen-by-browser"}', "content_type": "application/json"},
        )

    def check(self, module_test, events):
        responses = [e for e in events if e.type == "HTTP_RESPONSE"]
        rendered = [e for e in responses if "browser-dom" in e.tags and e.url == f"{HTTPSERVER_URL}/"]
        assert len(rendered) == 1
        assert "/js-built-link" in rendered[0].body
        # the response as served doesn't have it
        assert any("browser-dom" not in e.tags and "/js-built-link" not in e.body for e in responses)

        # excavate finds the link in the rendered DOM
        assert any(e.type == "URL_UNVERIFIED" and e.url.endswith("/js-built-link") for e in events)

        # requests the page's scripts made are emitted
        api = [e for e in events if e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/api/data"]
        assert api and str(api[0].module) == "browser_dom"
        assert "spider-danger" in api[0].tags
        assert "status-200" in api[0].tags

        # the http module turns it into a URL and HTTP_RESPONSE from the browser's copy, without requesting it again
        assert any(e.type == "URL" and e.url == f"{HTTPSERVER_URL}/api/data" for e in events)
        api_responses = [e for e in responses if e.url == f"{HTTPSERVER_URL}/api/data"]
        assert len(api_responses) == 1
        assert "seen-by-browser" in api_responses[0].body
        api_requests = [r for r, _ in module_test.httpserver.log if r.path == "/api/data"]
        assert len(api_requests) == 1

        # images aren't followed
        assert not any(e.type == "URL_UNVERIFIED" and e.url.endswith("/pixel.png") for e in events)
