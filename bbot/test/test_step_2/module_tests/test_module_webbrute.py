import re

from werkzeug.wrappers import Response

from .base import ModuleTestBase, tempwordlist
from bbot.test.worker import HTTPSERVER_URL


class TestWebBrute(ModuleTestBase):
    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["11111111", "admin", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "webbrute": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }
    modules_overrides = ["webbrute", "http"]

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/admin"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "admin" in e.url for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "11111111" in e.url for e in events)


class TestWebBrute2(TestWebBrute):
    test_wordlist = ["11111111", "console", "junkword1", "zzzjunkword2"]
    config_overrides = {"modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist), "extensions": "php"}}}

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/console.php"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "console" in e.url for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "11111111" in e.url for e in events)


class TestWebBrute_ignorecase(TestWebBrute):
    test_wordlist = ["11111111", "Admin", "admin", "zzzjunkword2"]
    config_overrides = {
        "modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist), "extensions": "php", "ignore_case": True}}
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/admin"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/Admin"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "admin" in e.url for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "Admin" in e.url for e in events)


class TestWebBruteHeaders(TestWebBrute):
    test_wordlist = ["11111111", "console", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist), "extensions": "php"}},
        "web": {"http_headers": {"test": "test2"}},
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "headers": {"test": "test2"}, "uri": "/console.php"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "console" in e.url for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "11111111" in e.url for e in events)


class TestWebBruteRedirectFalsePositive(ModuleTestBase):
    """Server returns 404 for random paths but 302->/ for ~-prefixed paths.
    webbrute should detect that all redirect hits go to the same location
    and filter them as false positives."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["~joe", "~", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "webbrute": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }
    modules_overrides = ["webbrute", "http"]

    def request_handler(self, request):
        uri = request.path
        if uri == "/":
            return Response("<html>Home</html>", status=200)
        if uri.lstrip("/").startswith("~"):
            return Response("", status=302, headers={"Location": "/"})
        return Response("Not Found", status=404)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        tilde_hits = [e for e in events if e.type == "URL_UNVERIFIED" and "~" in e.url and str(e.module) == "webbrute"]
        assert len(tilde_hits) == 0, (
            f"webbrute should not report redirect-to-root paths as findings, but got: {[e.url for e in tilde_hits]}"
        )


class TestWebBruteWAFFalsePositive(ModuleTestBase):
    """WAF returns 200 with block page body for certain paths.
    webbrute should detect WAF content and filter these as false positives."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["admin", "secret", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "webbrute": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }
    modules_overrides = ["webbrute", "http"]

    waf_body = "<html><head><title>Request Rejected</title></head><body>The requested URL was rejected. Please consult with your administrator.</body></html>"

    def request_handler(self, request):
        uri = request.path
        if uri == "/":
            return Response("<html>Home</html>", status=200)
        if uri.lstrip("/").startswith(("admin", "secret")):
            return Response(self.waf_body, status=200)
        return Response("Not Found", status=404)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        waf_hits = [
            e
            for e in events
            if e.type == "URL_UNVERIFIED" and str(e.module) == "webbrute" and ("admin" in e.url or "secret" in e.url)
        ]
        assert len(waf_hits) == 0, f"webbrute should filter WAF block pages, but got: {[e.url for e in waf_hits]}"


class TestWebBruteDynamicContentFilter(ModuleTestBase):
    """Server returns 200 with a per-request CSRF token for unknown paths.
    Without HttpCompare, the baseline would fall through to status-only filtering
    and report every 200 as a hit. HttpCompare should detect the token as a dynamic
    position and filter it out, only reporting /admin (genuinely different content)."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["admin", "junkword1", "zzzjunkword2"]
    config_overrides = {"modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist)}}}
    modules_overrides = ["webbrute", "http"]

    _counter = 0

    def request_handler(self, request):
        uri = request.path
        if uri == "/":
            return Response("<html>Home</html>", status=200)
        if uri.lstrip("/").startswith("admin"):
            return Response("<html><body>Admin Panel - Secret Content</body></html>", status=200)
        TestWebBruteDynamicContentFilter._counter += 1
        body = (
            "<html>\n"
            "<head><title>Page Not Found</title></head>\n"
            "<body>\n"
            "<p>The page you requested could not be found.</p>\n"
            f'<input type="hidden" name="csrf" value="tok{TestWebBruteDynamicContentFilter._counter:06d}"/>\n'
            "</body>\n"
            "</html>"
        )
        return Response(body, status=200)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        webbrute_urls = [e for e in events if e.type == "URL_UNVERIFIED" and str(e.module) == "webbrute"]
        assert any("admin" in e.url for e in webbrute_urls), (
            f"webbrute should find /admin (genuinely different), but got: {[e.url for e in webbrute_urls]}"
        )
        junk_hits = [e for e in webbrute_urls if "junkword" in e.url]
        assert len(junk_hits) == 0, (
            f"webbrute should filter dynamic-content false positives, but got: {[e.url for e in junk_hits]}"
        )


class TestWebBruteHitCap(ModuleTestBase):
    """Server returns unique content for every path, causing all words to pass
    HttpCompare. The sqrt-scaled hit cap should detect this as a filtering
    failure and discard everything before emission."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    # 50 words → cap of int(4 * sqrt(50)) = 28. All 50 will "hit", exceeding the cap.
    test_wordlist = [f"word{i:03d}" for i in range(50)]
    config_overrides = {"modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist)}}}
    modules_overrides = ["webbrute", "http"]

    _counter = 0

    def request_handler(self, request):
        uri = request.path
        if uri == "/":
            return Response("<html>Home</html>", status=200)
        # Return unique content only for wordlist words (word000-word049).
        # Random strings (like the canary) get a normal 404 so the canary
        # doesn't mask the hit cap.
        segment = uri.strip("/")
        if segment.startswith("word"):
            TestWebBruteHitCap._counter += 1
            body = f"<html><body>Unique page {TestWebBruteHitCap._counter} for {uri}</body></html>"
            return Response(body, status=200)
        return Response("Not Found", status=404)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        webbrute_urls = [e for e in events if e.type == "URL_UNVERIFIED" and str(e.module) == "webbrute"]
        assert len(webbrute_urls) == 0, (
            f"Hit cap should have discarded all hits, but got: {[e.url for e in webbrute_urls]}"
        )


class TestWebBruteCanaryDefense(ModuleTestBase):
    """Server returns unique content for EVERY path including random strings.
    The canary fires and aborts, discarding all hits."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["admin", "secret", "login"]
    config_overrides = {"modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist)}}}
    modules_overrides = ["webbrute", "http"]

    _counter = 0

    def request_handler(self, request):
        uri = request.path
        if uri == "/":
            return Response("<html>Home</html>", status=200)
        # Every path (including random canary strings) gets unique content
        # that differs structurally from the baseline, not just in a filterable position.
        TestWebBruteCanaryDefense._counter += 1
        n = TestWebBruteCanaryDefense._counter
        extra = "".join(f"<p>Section {i}</p>\n" for i in range(n % 5 + 1))
        body = f"<html><body><h1>Custom page #{n} for {uri}</h1>\n{extra}</body></html>"
        return Response(body, status=200)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        webbrute_urls = [e for e in events if e.type == "URL_UNVERIFIED" and str(e.module) == "webbrute"]
        assert len(webbrute_urls) == 0, (
            f"Canary defense should have aborted, but webbrute emitted: {[e.url for e in webbrute_urls]}"
        )


class TestWebBruteMidScanBaselineDrift(ModuleTestBase):
    """Server matches baseline initially, then drifts (WAF kicks in after N requests).
    Mid-scan baseline check should detect the drift and abort."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["admin", "secret", "login"]
    config_overrides = {"modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist)}}}
    modules_overrides = ["webbrute", "http"]

    _request_count = 0

    def request_handler(self, request):
        uri = request.path
        if uri == "/":
            return Response("<html>Home</html>", status=200)
        TestWebBruteMidScanBaselineDrift._request_count += 1
        # First 4 requests: normal 404 (baseline probes + early fuzz).
        # After that: WAF kicks in, returns block page for everything.
        if TestWebBruteMidScanBaselineDrift._request_count <= 4:
            return Response("Not Found", status=404)
        return Response("<html>Access Denied by WAF</html>", status=200)

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=self.request_handler)

    def check(self, module_test, events):
        webbrute_urls = [e for e in events if e.type == "URL_UNVERIFIED" and str(e.module) == "webbrute"]
        assert len(webbrute_urls) == 0, (
            f"Mid-scan baseline drift should have aborted, but webbrute emitted: {[e.url for e in webbrute_urls]}"
        )


class TestWebBruteWildcardSkip(ModuleTestBase):
    """When the host is an HTTP wildcard, webbrute should skip fuzzing entirely."""

    targets = [HTTPSERVER_URL]
    module_name = "webbrute"
    test_wordlist = ["admin", "secret"]
    config_overrides = {"modules": {"webbrute": {"wordlist": tempwordlist(test_wordlist)}}}
    modules_overrides = ["webbrute", "http"]

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/admin"},
            respond_args={"response_data": "alive admin page"},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": "alive"},
        )

    async def setup_after_prep(self, module_test):
        async def mock_wildcard(scheme, host, port):
            return True

        module_test.scan.helpers.web.is_http_wildcard_host = mock_wildcard

    def check(self, module_test, events):
        webbrute_urls = [e for e in events if e.type == "URL_UNVERIFIED" and str(e.module) == "webbrute"]
        assert len(webbrute_urls) == 0, (
            f"webbrute should not fuzz wildcard hosts, but emitted: {[e.url for e in webbrute_urls]}"
        )
