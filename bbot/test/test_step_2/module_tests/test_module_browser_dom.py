import re

import pytest
from werkzeug.wrappers import Response

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


REDIRECT_PAGE = """<html><head><title>leaving</title></head><body><script>
document.body.insertAdjacentHTML("beforeend", "<a href='/only-before-leaving'>x</a>");
location.href = "/destination";
</script></body></html>"""


class TestBrowserDomJsRedirect(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/leaving"]
    # both browser modules share the page load, and the destination is emitted once between them
    modules_overrides = ["http", "browser_dom", "screenshot"]
    config_overrides = {"web": {"enable_browser": True}, "excavate": True}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            {"uri": "/leaving"}, {"response_data": REDIRECT_PAGE, "content_type": "text/html"}
        )
        module_test.set_expect_requests(
            {"uri": "/destination"}, {"response_data": "<html>destination</html>", "content_type": "text/html"}
        )

    def check(self, module_test, events):
        # the page as its script left it, kept instead of following the redirect
        rendered = [e for e in events if e.type == "HTTP_RESPONSE" and "browser-dom" in e.tags]
        leaving = [e for e in rendered if e.url == f"{HTTPSERVER_URL}/leaving"]
        assert len(leaving) == 1
        assert "js-redirect" in leaving[0].tags
        assert "/only-before-leaving" in leaving[0].body

        destinations = [e for e in events if e.type == "URL_UNVERIFIED" and "js-redirect" in e.tags]
        assert len(destinations) == 1
        assert destinations[0].url == f"{HTTPSERVER_URL}/destination"
        # like an HTTP redirect, it doesn't count as spidering
        assert "spider-danger" not in destinations[0].tags
        # and it's then visited in its own right
        assert any(e.type == "URL" and e.url == f"{HTTPSERVER_URL}/destination" for e in events)


# requests only the page's scripts send, with a cookie and a header the page sets itself
PARAMETERS_PAGE = """<html><head><title>parameters</title></head><body><script>
document.cookie = "session=abc123; path=/";
const token = {"X-CSRF-Token": "tok123"};
fetch("/api/items?category=books&page=2&_ga=GA1.1", {headers: token});
fetch("/api/search?v=1", {
    method: "POST",
    headers: {...token, "Content-Type": "application/json"},
    body: JSON.stringify({q: "hello", limit: 10, filter: {lang: "en"}}),
});
const form = new XMLHttpRequest();
form.open("POST", "/api/save");
form.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
form.send("title=draft&tags=a%2Cb");
// the same call again, with other values
fetch("/api/items?category=films&page=3", {headers: token});
</script></body></html>"""


class TestBrowserDomParameters(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [HTTPSERVER_URL]
    # hunt tests parameters, which is what has browser_dom emit them
    modules_overrides = ["http", "browser_dom", "hunt"]
    config_overrides = {"web": {"enable_browser": True}, "excavate": True}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": PARAMETERS_PAGE, "content_type": "text/html"})
        for uri in ("/api/items", "/api/search", "/api/save"):
            module_test.set_expect_requests(
                {"uri": uri}, {"response_data": '{"ok": true}', "content_type": "application/json"}
            )

    def check(self, module_test, events):
        parameters = {}
        for e in events:
            if e.type == "WEB_PARAMETER" and str(e.module) == "browser_dom":
                key = (e.data["type"], e.data["name"])
                assert key not in parameters, f"{key} emitted twice"
                parameters[key] = e.data

        items = parameters[("GETPARAM", "category")]
        assert items["url"] == f"{HTTPSERVER_URL}/api/items"
        # the first time the page sent it, with everything else it sent then
        assert items["original_value"] == "books"
        assert items["additional_params"] == {"page": "2", "_ga": "GA1.1"}
        assert items["assigned_cookies"] == {"session": "abc123"}
        assert items["assigned_headers"].get("x-csrf-token") == "tok123"
        assert not {"user-agent", "accept", "cookie"} & set(items["assigned_headers"])
        assert items["host_url"] == f"{HTTPSERVER_URL}/"
        assert items["content_type"].startswith("application/json")
        assert ("GETPARAM", "page") in parameters
        assert ("GETPARAM", "_ga") not in parameters, "a blacklisted parameter was emitted"

        search = parameters[("BODYJSON", "q")]
        # a POST's query stays on its URL, and isn't a parameter of its own
        assert search["url"] == f"{HTTPSERVER_URL}/api/search?v=1"
        assert ("GETPARAM", "v") not in parameters
        assert search["original_value"] == "hello"
        assert search["additional_params"] == {"limit": 10, "filter": {"lang": "en"}}
        assert parameters[("BODYJSON", "limit")]["original_value"] == "10"
        assert parameters[("BODYJSON", "filter")]["original_value"] == '{"lang": "en"}'

        save = parameters[("POSTPARAM", "title")]
        assert save["url"] == f"{HTTPSERVER_URL}/api/save"
        assert save["additional_params"] == {"tags": "a,b"}

        # an endpoint the page posts to isn't a page to fetch
        urls = {e.url for e in events if e.type == "URL_UNVERIFIED" and str(e.module) == "browser_dom"}
        assert f"{HTTPSERVER_URL}/api/items" in urls
        assert not {f"{HTTPSERVER_URL}/api/search", f"{HTTPSERVER_URL}/api/save"} & urls
        assert not [r for r, _ in module_test.httpserver.log if r.path == "/api/save" and r.method == "GET"]


# a search the page's script runs, which only answers a request carrying the page's header, cookie and other parameter
GATED_PAGE = """<html><head><title>gated</title></head><body><script>
document.cookie = "session=abc123; path=/";
fetch("/search?q=hello&page=1", {headers: {"X-Token": "secret"}});
</script></body></html>"""


class TestBrowserDomParametersLightfuzz(ModuleTestBase):
    """lightfuzz tests a parameter only the page's script sends, as the script sent it"""

    pytestmark = pytest.mark.browser
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "browser_dom", "lightfuzz"]
    config_overrides = {
        "web": {"enable_browser": True},
        "excavate": True,
        "interactsh_disable": True,
        "modules": {"lightfuzz": {"enabled_submodules": ["xss"]}},
    }

    def search(self, request):
        gated = (
            request.headers.get("X-Token") == "secret"
            and request.cookies.get("session") == "abc123"
            and request.args.get("page") == "1"
        )
        if not gated:
            return Response("", status=200, content_type="text/html")
        return Response(
            f"<html><body><h1>results for '{request.args.get('q', '')}'</h1></body></html>",
            status=200,
            content_type="text/html",
        )

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: (
            "1234567890" if kwargs.get("numeric_only") else "AAAAAAAAAAAAAA"
        )
        module_test.set_expect_requests({"uri": "/"}, {"response_data": GATED_PAGE, "content_type": "text/html"})
        module_test.set_expect_requests_handler(expect_args=re.compile("/search"), request_handler=self.search)

    def check(self, module_test, events):
        assert any(
            e.type == "WEB_PARAMETER" and str(e.module) == "browser_dom" and e.data["name"] == "q" for e in events
        )
        assert any(
            e.type == "FINDING" and "Possible Reflected XSS. Parameter: [q]" in e.data["description"] for e in events
        ), "lightfuzz didn't find the XSS behind the header, cookie and other parameter"


# a search form and a link that only exist once the script runs: no name or path below is in the source as served
RENDERED_PAGE = """<html><head><title>rendered</title></head><body><script>
const form = document.createElement("form");
form.setAttribute("action", "/sea" + "rch");
form.setAttribute("method", "get");
const term = document.createElement("input");
term.setAttribute("name", "te" + "rm");
term.setAttribute("value", "shoes");
form.appendChild(term);
const language = document.createElement("input");
language.setAttribute("type", "hidden");
language.setAttribute("name", "la" + "ng");
language.setAttribute("value", "en");
form.appendChild(language);
document.body.appendChild(form);
const link = document.createElement("a");
link.setAttribute("href", "/it" + "em?i" + "d=" + (40 + 2) + "&re" + "f=home");
document.body.appendChild(link);
</script></body></html>"""


class TestBrowserDomRenderedParameters(ModuleTestBase):
    """Excavate finds the parameters of forms and links that only exist in the page browser_dom rendered"""

    pytestmark = pytest.mark.browser
    targets = [HTTPSERVER_URL]
    # hunt tests parameters, which is what turns on excavate's parameter extraction
    modules_overrides = ["http", "browser_dom", "hunt"]
    config_overrides = {"web": {"enable_browser": True}, "excavate": True}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": RENDERED_PAGE, "content_type": "text/html"})

    def check(self, module_test, events):
        parameters = {
            e.data["name"]: e
            for e in events
            if e.type == "WEB_PARAMETER" and e.data["type"] == "GETPARAM" and str(e.module) == "excavate"
        }

        term = parameters["term"]
        assert term.data["url"] == f"{HTTPSERVER_URL}/search"
        assert term.data["original_value"] == "shoes"
        assert term.data["additional_params"] == {"lang": "en"}

        item = parameters["id"]
        assert item.data["url"] == f"{HTTPSERVER_URL}/item"
        assert item.data["original_value"] == "42"
        assert item.data["additional_params"] == {"ref": "home"}

        # both found in the page as the browser rendered it, not as it was served
        for parameter in (term, item):
            assert parameter.parent.type == "HTTP_RESPONSE"
            assert "browser-dom" in parameter.parent.tags
