import time

from werkzeug.wrappers import Response

from .base import ModuleTestBase
from bbot.test.worker import (
    HTTPSERVER_HOSTPORT,
    HTTPSERVER_PORT,
    HTTPSERVER_SSL_PORT,
    HTTPSERVER_SSL_URL,
    HTTPSERVER_URL,
)


class TestHTTPBase(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/url", HTTPSERVER_HOSTPORT]
    module_name = "http"
    modules_overrides = ["http", "excavate"]
    config_overrides = {"modules": {"http": {"store_responses": True}}}

    # HTML for a page with a login form
    html_with_login = """
<html>
<body>
    <form>
        <input type="text" name="username">
        <input name="password">
        <input type="submit" value="Login">
    </form>
</body>
</html>"""

    # HTML for a page without a login form
    html_without_login = """
<html>
<body>
    <form>
        <input type="text" name="search">
        <input type="submit" value="Search">
    </form>
</body>
</html>"""

    async def setup_after_prep(self, module_test):
        request_args = {"uri": "/", "headers": {"test": "header"}}
        respond_args = {"response_data": self.html_without_login}
        module_test.set_expect_requests(request_args, respond_args)
        request_args = {"uri": "/url", "headers": {"test": "header"}}
        respond_args = {"response_data": self.html_with_login}
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        url = False
        open_port = False
        for e in events:
            if e.type == "HTTP_RESPONSE":
                if e.data["path"] == "/":
                    assert "login-page" not in e.tags
                    open_port = True
                elif e.data["path"] == "/url":
                    assert "login-page" in e.tags
                    url = True
        assert url, "Failed to visit target URL"
        assert open_port, "Failed to visit target OPEN_TCP_PORT"
        # The http module encodes host:port into the filename with a dot separator.
        saved_response = module_test.scan.home / "http_responses" / f"127.0.0.1.{HTTPSERVER_PORT}[slash]url.txt"
        assert saved_response.is_file(), "Failed to save raw http response"


class TestHTTP_404(ModuleTestBase):
    targets = [HTTPSERVER_SSL_URL]
    modules_overrides = ["http", "speculate", "excavate"]
    config_overrides = {"modules": {"speculate": {"ports": f"{HTTPSERVER_PORT},{HTTPSERVER_SSL_PORT}"}}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "Redirecting...", status=301, headers={"Location": HTTPSERVER_SSL_URL}
        )
        module_test.httpserver_ssl.expect_request("/").respond_with_data("404 not found", status=404)

    def check(self, module_test, events):
        assert 1 == len(
            [e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/" and "status-301" in e.tags]
        )
        assert 1 == len([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_SSL_URL}/"])


class TestHTTP_Redirect(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "speculate", "excavate"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "Redirecting...", status=301, headers={"Location": "http://www.evilcorp.com"}
        )

    def check(self, module_test, events):
        assert 1 == len(
            [e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/" and "status-301" in e.tags]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED" and e.url == "http://www.evilcorp.com/" and "affiliate" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type.startswith("DNS_NAME") and e.data == "www.evilcorp.com" and "affiliate" in e.tags
            ]
        )


class TestHTTP_URLBlacklist(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "speculate", "excavate"]
    config_overrides = {"web": {"spider_distance": 10, "spider_depth": 10}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            """
            <a href="/test.aspx"/>
            <a href="/test.svg"/>
            <a href="/test.woff2"/>
            <a href="/test.txt"/>
            """
        )

    def check(self, module_test, events):
        assert 4 == len([e for e in events if e.type == "URL_UNVERIFIED"])
        assert 3 == len([e for e in events if e.type == "HTTP_RESPONSE"])
        assert 3 == len([e for e in events if e.type == "URL"])
        assert 1 == len([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/"])
        assert 1 == len([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/test.aspx"])
        assert 1 == len([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/test.txt"])
        assert not any(e for e in events if "URL" in e.type and ".svg" in e.url)
        assert not any(e for e in events if "URL" in e.type and ".woff" in e.url)


class TestHTTP_querystring_removed(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "speculate", "excavate"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data('<a href="/test.php?foo=bar"/>')

    def check(self, module_test, events):
        assert [e for e in events if e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/test.php"]


class TestHTTP_querystring_notremoved(TestHTTP_querystring_removed):
    config_overrides = {"url_querystring_remove": False}

    def check(self, module_test, events):
        assert [e for e in events if e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/test.php?foo=bar"]


class TestHTTP_custom_headers(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "speculate", "excavate"]
    config_overrides = {"web": {"http_headers": {"testheader": "testvalue"}}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/", headers={"testheader": "testvalue"}).respond_with_data("alive")

    def check(self, module_test, events):
        # Ensure we received the expected response when the header was present
        assert [e for e in events if e.type == "URL" and "status-200" in e.tags]


class TestHTTP_custom_cookies(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "speculate", "excavate"]
    config_overrides = {"web": {"http_cookies": {"testcookie": "cookievalue"}}}

    async def setup_after_prep(self, module_test):
        # Expect a request to "/" with the custom cookie 'testcookie=cookievalue'
        module_test.httpserver.expect_request("/", headers={"cookie": "testcookie=cookievalue"}).respond_with_data(
            "alive"
        )

    def check(self, module_test, events):
        # Ensure we received the expected response when the cookie was present
        assert [e for e in events if e.type == "URL" and "status-200" in e.tags]


class TestHTTP_429_retry(ModuleTestBase):
    """Test the module's own defer→cooldown→retry→succeed path.

    http_retries=1 means blasthttp makes up to 2 wire attempts per request.
    We return 429 for the first 2 requests (exhausting blasthttp's retry),
    so the module's 429 handler engages and defers with a cooldown. The 3rd
    request (from the module's retry after cooldown) succeeds.
    """

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http"]
    config_overrides = {"web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1}}

    async def setup_after_prep(self, module_test):
        self.request_count = 0

        def handler(request):
            self.request_count += 1
            if self.request_count <= 2:
                return Response("rate limited", status=429, headers={"Retry-After": "1"})
            return Response("<html><body>OK</body></html>")

        module_test.httpserver.expect_request("/").respond_with_handler(handler)

    def check(self, module_test, events):
        assert self.request_count >= 3, "Expected at least 3 requests (2 blasthttp attempts + 1 module retry)"
        assert any(e.type == "URL" and "status-200" in e.tags for e in events), (
            "Expected URL with status-200 after successful retry"
        )
        assert not any(e.type == "URL" and "status-429" in e.tags for e in events), (
            "429 response should not be emitted as a URL event"
        )


class TestHTTP_url_metadata(ModuleTestBase):
    """White-box test of make_url_metadata's OPEN_TCP_PORT probe set.

    Well-known ports only probe their matching scheme (443→https, 80→http);
    every other port probes both. url_hash stays scheme-independent so incoming
    dedup is unaffected, and IPv6 hosts get bracketed netlocs.
    """

    targets = [HTTPSERVER_URL]
    module_name = "http"
    modules_overrides = ["http"]

    def check(self, module_test, events):
        module = module_test.module
        make_event = module_test.scan.make_event

        e443 = make_event("127.0.0.1:443", "OPEN_TCP_PORT", dummy=True)
        urls, url_hash = module.make_url_metadata(e443)
        assert urls == ["https://127.0.0.1:443/"], "port 443 should probe https only"
        # url_hash is scheme-independent, so OPEN_TCP_PORT dedup is unaffected
        assert url_hash == hash((e443.host, e443.port, False))

        e80 = make_event("127.0.0.1:80", "OPEN_TCP_PORT", dummy=True)
        urls, _ = module.make_url_metadata(e80)
        assert urls == ["http://127.0.0.1:80/"], "port 80 should probe http only"

        e8080 = make_event("127.0.0.1:8080", "OPEN_TCP_PORT", dummy=True)
        urls, _ = module.make_url_metadata(e8080)
        assert urls == ["http://127.0.0.1:8080/", "https://127.0.0.1:8080/"], (
            "non-well-known ports should probe both schemes"
        )

        e6 = make_event("[dead::beef]:8080", "OPEN_TCP_PORT", dummy=True)
        urls, _ = module.make_url_metadata(e6)
        assert urls == ["http://[dead::beef]:8080/", "https://[dead::beef]:8080/"], (
            "IPv6 hosts should produce bracketed netlocs"
        )


class TestHTTP_429_give_up(ModuleTestBase):
    """A site that answers nothing but 429 for `rate_limit_give_up` seconds is given up on, and its URLs dropped."""

    targets = [HTTPSERVER_URL]
    module_name = "http"
    modules_overrides = ["http"]
    config_overrides = {
        "web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1},
        "modules": {"http": {"rate_limit_give_up": 3}},
    }

    async def setup_after_prep(self, module_test):
        self.request_count = 0

        def handler(request):
            self.request_count += 1
            return Response("rate limited", status=429, headers={"Retry-After": "1"})

        module_test.httpserver.expect_request("/").respond_with_handler(handler)

    async def check(self, module_test, events):
        assert self.request_count >= 2, "Expected at least one retry before giving up"
        assert not any(e.type == "URL" and "status-429" in e.tags for e in events), (
            "Exhausted 429 retries should not emit a URL event"
        )
        assert not any(e.type == "HTTP_RESPONSE" and e.data.get("status_code") == 429 for e in events), (
            "Exhausted 429 retries should not emit an HTTP_RESPONSE event"
        )
        module = module_test.module
        assert module._rate_limits["127.0.0.1"].gave_up
        # and a URL found later on the same site isn't tried
        later = module_test.scan.make_event(f"{HTTPSERVER_URL}/later", "URL_UNVERIFIED", dummy=True)
        assert (await module.filter_event(later))[0] is False


class TestHTTP_429_test_request(ModuleTestBase):
    """
    A 429 pauses the whole site and holds its URLs. When the pause ends, one of them goes out to test whether the site
    is still rate limiting, and the rest follow once one gets through.
    """

    paths = ["/a", "/b", "/c", "/d"]
    targets = [f"{HTTPSERVER_URL}{path}" for path in paths]
    module_name = "http"
    modules_overrides = ["http"]
    # one request per URL, so each 429 the server sends is one the module saw
    config_overrides = {"web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1, "http_retries": 0}}
    # the site rate limits for this long after its first request
    limited_for = 2.5

    async def setup_after_prep(self, module_test):
        self.requests = []

        def handler(request):
            now = time.monotonic()
            if not self.requests:
                self.first = now
            if now - self.first < self.limited_for:
                self.requests.append((now, 429))
                return Response("rate limited", status=429, headers={"Retry-After": "1"})
            self.requests.append((now, 200))
            return Response("<html><body>OK</body></html>")

        for path in self.paths:
            module_test.httpserver.expect_request(path).respond_with_handler(handler)

    def check(self, module_test, events):
        # every URL got through in the end
        urls = {e.parsed_url.path for e in events if e.type == "URL" and "status-200" in e.tags}
        assert urls == set(self.paths)
        assert not any(e.type == "URL" and "status-429" in e.tags for e in events)

        # after the first requests, the site only saw one test request per pause
        limited = [t for t, status in self.requests if status == 429]
        tests = [t for t in limited if t - limited[0] > 0.5]
        assert tests, "expected a test request that was still rate limited"
        for previous, test in zip([limited[0]] + tests, tests):
            assert test - previous >= 0.8, f"test requests {test - previous:.2f}s apart"

        # sites are registered domains, counting shared hosts' customers as sites of their own
        site = module_test.module._site
        assert site("www.evilcorp.com") == site("app.evilcorp.com") == "evilcorp.com"
        assert site("www.evilcorp.co.uk") == "evilcorp.co.uk"
        assert site("evilcorp.herokuapp.com") != site("othercorp.herokuapp.com")
        assert site("127.0.0.1") == "127.0.0.1"
