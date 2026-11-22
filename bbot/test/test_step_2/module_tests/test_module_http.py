import pytest
import asyncio
import socket
import threading
import time

import blasthttp
from werkzeug.wrappers import Response

from .base import ModuleTestBase
from bbot.test.worker import (
    HTTPSERVER_HOSTPORT,
    HTTPSERVER_PORT,
    HTTPSERVER_SSL_HOSTPORT,
    HTTPSERVER_SSL_PORT,
    HTTPSERVER_SSL_URL,
    HTTPSERVER_URL,
    LOCALHOST_HOSTPORT,
    LOCALHOST_URL,
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
    """
    A 429 holds the URL, and the module sends it again once the pause ends.

    The first two requests get a 429: the batch's, then the drain's first test request. The third gets through.
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
        assert self.request_count >= 3, "Expected at least 3 requests (the batch's, then two from the drain)"
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
    """A host:port that answers nothing but 429 for `rate_limit_give_up` seconds is given up on, and its URLs dropped."""

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
        assert not any(e.type == "URL" and "status-429" in e.tags for e in events), "A 429 should not emit a URL event"
        assert not any(e.type == "HTTP_RESPONSE" and e.data.get("status_code") == 429 for e in events), (
            "A 429 should not emit an HTTP_RESPONSE event"
        )
        module = module_test.module
        assert HTTPSERVER_HOSTPORT in module._gave_up
        # and a URL found later on the same host:port isn't tried
        later = module_test.scan.make_event(f"{HTTPSERVER_URL}/later", "URL_UNVERIFIED", dummy=True)
        assert (await module.filter_event(later))[0] is False


class TestHTTP_429_test_request(ModuleTestBase):
    """
    A 429 pauses its host:port and holds its URLs. When the pause ends, one of them goes out to test whether it's still
    rate limiting, and the rest follow once one gets through.
    """

    paths = ["/a", "/b", "/c", "/d"]
    targets = [f"{HTTPSERVER_URL}{path}" for path in paths]
    module_name = "http"
    modules_overrides = ["http"]
    # blasthttp leaves a 429 to the module, so each one the server sends is one the module saw
    config_overrides = {"web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1}}
    # the host rate limits for this long after its first request
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

        # after the first requests, the host only saw one test request per pause
        limited = [t for t, status in self.requests if status == 429]
        tests = [t for t in limited if t - limited[0] > 0.5]
        assert tests, "expected a test request that was still rate limited"
        for previous, test in zip([limited[0]] + tests, tests):
            assert test - previous >= 0.8, f"test requests {test - previous:.2f}s apart"


OK_PAGE = "<html><body>OK</body></html>"


def too_many(retry_after="1"):
    return Response("rate limited", status=429, headers={"Retry-After": retry_after})


class HTTP429Base(ModuleTestBase):
    """Stops a scan still running after `deadline` seconds, so a hang fails the test instead of the whole run."""

    module_name = "http"
    modules_overrides = ["http"]
    # blasthttp leaves a 429 to the module, so each one the server sends is one the module saw
    config_overrides = {"web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1}}
    deadline = 30

    async def _execute_scan(self, module_test):
        task = asyncio.create_task(super()._execute_scan(module_test))
        done, _ = await asyncio.wait({task}, timeout=self.deadline)
        if not done:
            await module_test.scan.async_stop()
            await asyncio.wait({task}, timeout=30)
        assert done, f"scan still running after {self.deadline}s"

    async def wait_for(self, condition, timeout=20):
        """Wait for `condition()`, failing after `timeout` seconds rather than polling for the rest of the run."""

        async def poll():
            while not condition():
                await asyncio.sleep(0.02)

        await asyncio.wait_for(poll(), timeout)

    async def wait_until_held(self, module_test, netloc):
        await self.wait_for(lambda: netloc in module_test.module._held)

    async def inject(self, module_test, data, event_type="URL_UNVERIFIED", prefetched_response=None):
        scan = module_test.scan
        module = scan._make_dummy_module(name="TEST", _type="TEST")
        event = scan.make_event(data, event_type, parent=scan.root_event, module=module, context="{event.data}")
        event.prefetched_response = prefetched_response
        await scan.ingress_module.queue_event(event, {})


class TestHTTP_429_drain_error(HTTP429Base):
    """An error while sending held URLs loses them, but doesn't keep the scan from finishing."""

    targets = [f"{HTTPSERVER_URL}/a"]

    async def setup_after_prep(self, module_test):
        self.requests = 0

        def handler(request):
            self.requests += 1
            return too_many() if self.requests == 1 else Response(OK_PAGE)

        module_test.httpserver.expect_request("/a").respond_with_handler(handler)

        async def broken(*args, **kwargs):
            raise RuntimeError("broken")

        module_test.monkeypatch.setattr(module_test.module, "_process_result", broken)

    def check(self, module_test, events):
        assert self.requests == 2, "the held URL was never sent"
        assert not module_test.module._held


class TestHTTP_429_killed(HTTP429Base):
    """Killing the module while it holds URLs doesn't keep the scan from finishing, even mid-pause."""

    targets = [f"{HTTPSERVER_URL}/a"]
    config_overrides = {"web": {"429_sleep_interval": 60, "429_max_sleep_interval": 60}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/a").respond_with_handler(lambda request: too_many("60"))

        async def kill():
            await self.wait_until_held(module_test, HTTPSERVER_HOSTPORT)
            module_test.scan.kill_module("http", message="killed by test")

        self.killer = asyncio.create_task(kill())

    def check(self, module_test, events):
        assert module_test.module.errored


class TestHTTP_429_held_during_pause(HTTP429Base):
    """
    URLs found while a host:port is paused wait for it, but its pause doesn't hold another hostname on the same port,
    or another port on the same host.
    """

    targets = [f"{HTTPSERVER_URL}/a", f"{LOCALHOST_URL}/a", f"{HTTPSERVER_SSL_URL}/a"]
    limited = HTTPSERVER_HOSTPORT
    limited_for = 3

    async def setup_after_prep(self, module_test):
        self.requests = []
        self.lock = threading.Lock()
        self.first = None

        def handler(request):
            with self.lock:
                now = time.monotonic()
                status = 200
                if request.host == self.limited and request.scheme == "http":
                    self.first = self.first or now
                    if now - self.first < self.limited_for:
                        status = 429
                self.requests.append((now, request.host, request.scheme, request.path, status))
            return too_many() if status == 429 else Response(OK_PAGE)

        for server in (module_test.httpserver, module_test.httpserver_ssl):
            for path in ("/a", "/late"):
                server.expect_request(path).respond_with_handler(handler)

        async def inject():
            await self.wait_until_held(module_test, self.limited)
            self.injected_at = time.monotonic()
            for url in (HTTPSERVER_URL, LOCALHOST_URL, HTTPSERVER_SSL_URL):
                await self.inject(module_test, f"{url}/late")

        self.injector = asyncio.create_task(inject())

    def check(self, module_test, events):
        got = {(e.parsed_url.netloc, e.parsed_url.path) for e in events if e.type == "URL" and "status-200" in e.tags}
        for netloc in (HTTPSERVER_HOSTPORT, LOCALHOST_HOSTPORT, HTTPSERVER_SSL_HOSTPORT):
            assert (netloc, "/late") in got, f"{netloc}/late never got through"

        # the other hostname and the other port weren't held
        for t, host, scheme, path, _ in self.requests:
            if path == "/late" and (host, scheme) != (self.limited, "http"):
                assert t - self.injected_at < 0.75, f"{scheme}://{host}{path} waited {t - self.injected_at:.2f}s"

        # while it was rate limiting, the paused host:port got one request per pause
        limited = [t for t, *_, status in self.requests if status == 429]
        for a, b in zip(limited, limited[1:]):
            assert b - a >= 0.8, f"two requests {b - a:.2f}s apart while {self.limited} was rate limiting"


class TestHTTP_429_open_port(HTTP429Base):
    """An OPEN_TCP_PORT's URL is held and sent like any other, and its other scheme failing TLS isn't a recovery."""

    targets = [HTTPSERVER_HOSTPORT, f"{HTTPSERVER_URL}/b", f"{HTTPSERVER_URL}/c"]
    limited_for = 3.5

    async def setup_after_prep(self, module_test):
        self.requests = []
        self.lock = threading.Lock()
        self.first = None

        def handler(request):
            with self.lock:
                now = time.monotonic()
                self.first = self.first or now
                status = 429 if now - self.first < self.limited_for else 200
                self.requests.append((now, request.path, status))
            return too_many() if status == 429 else Response(OK_PAGE)

        for path in ("/", "/b", "/c"):
            module_test.httpserver.expect_request(path).respond_with_handler(handler)

    def check(self, module_test, events):
        got = {e.parsed_url.path for e in events if e.type == "URL" and "status-200" in e.tags}
        assert got >= {"/", "/b", "/c"}, f"got {got}"
        limited = [t for t, _, status in self.requests if status == 429]
        later = [t for t in limited if t - limited[0] > 0.5]
        for a, b in zip(later, later[1:]):
            assert b - a >= 0.8, f"two requests {b - a:.2f}s apart while still rate limiting: {self.requests}"


class TestHTTP_429_token_bucket(HTTP429Base):
    """
    Against a token bucket that allows no burst, the held URLs all get through, with a bounded number of 429s each,
    rather than every held URL going out again after every pause.
    """

    paths = [f"/p{i}" for i in range(16)]
    targets = [f"{HTTPSERVER_URL}{path}" for path in paths]
    rate = 4
    deadline = 60

    async def setup_after_prep(self, module_test):
        self.requests = []
        self.lock = threading.Lock()
        self.tokens = 1.0
        self.last = time.monotonic()

        def handler(request):
            with self.lock:
                now = time.monotonic()
                self.tokens = min(1.0, self.tokens + (now - self.last) * self.rate)
                self.last = now
                ok = self.tokens >= 1
                if ok:
                    self.tokens -= 1
                self.requests.append((now, request.path, 200 if ok else 429))
            return Response(OK_PAGE) if ok else too_many()

        for path in self.paths:
            module_test.httpserver.expect_request(path).respond_with_handler(handler)

    def check(self, module_test, events):
        got = {e.parsed_url.path for e in events if e.type == "URL" and "status-200" in e.tags}
        assert got == set(self.paths), f"missing {set(self.paths) - got}"
        assert len(self.requests) <= 4 * len(self.paths), f"{len(self.requests)} requests for {len(self.paths)} URLs"


class TestHTTP_429_pause_capped(HTTP429Base):
    """Without a Retry-After, a 429 pauses for 429_sleep_interval, capped at 429_max_sleep_interval."""

    targets = [HTTPSERVER_URL]
    config_overrides = {"web": {"429_sleep_interval": 30, "429_max_sleep_interval": 1}}

    async def setup_after_prep(self, module_test):
        self.requests = []

        def handler(request):
            self.requests.append(time.monotonic())
            if len(self.requests) == 1:
                return Response("rate limited", status=429)
            return Response(OK_PAGE)

        module_test.httpserver.expect_request("/").respond_with_handler(handler)

    def check(self, module_test, events):
        assert len(self.requests) == 2
        assert 0.8 <= self.requests[1] - self.requests[0] < 5, f"paused {self.requests[1] - self.requests[0]:.2f}s"


class TestHTTP_429_left_to_the_module(HTTP429Base):
    """
    Every request asks blasthttp to retry dropped connections as usual but leave a 429 alone, and the batch and the
    drains share one concurrency limit.
    """

    targets = [f"{HTTPSERVER_URL}/a"]

    async def setup_after_prep(self, module_test):
        self.requests = 0

        def handler(request):
            self.requests += 1
            return too_many() if self.requests == 1 else Response(OK_PAGE)

        module_test.httpserver.expect_request("/a").respond_with_handler(handler)

        real = module_test.module.client
        self.configs, self.limits = [], []
        test = self

        class Recording:
            def __getattr__(self, name):
                return getattr(real, name)

            def request_batch_stream(self, configs, **kwargs):
                test.configs.extend(configs)
                test.limits.append(kwargs.get("concurrency"))
                return real.request_batch_stream(configs, **kwargs)

        module_test.module.client = Recording()

    def check(self, module_test, events):
        module = module_test.module
        # the batch, then the drain
        assert len(self.configs) == 2
        assert all(c.retry_statuses == [] for c in self.configs)
        assert all(c.retries == module_test.scan.http_retries for c in self.configs)
        assert all(limit is module._concurrency for limit in self.limits)
        assert module._concurrency.size == module.threads


class TestHTTP_429_no_answer_is_not_a_recovery(HTTP429Base):
    """
    A held URL that gets no answer, like https:// on a plain-http port, says nothing about whether the host:port has
    stopped rate limiting, so the next round goes out no bigger than the last.
    """

    targets = [f"{HTTPSERVER_URL}/a"]
    limited_for = 6

    async def setup_after_prep(self, module_test):
        self.requests = []
        self.lock = threading.Lock()
        self.first = None

        def handler(request):
            with self.lock:
                now = time.monotonic()
                self.first = self.first or now
                status = 429 if now - self.first < self.limited_for else 200
                self.requests.append((now, request.path, status))
            return too_many() if status == 429 else Response(OK_PAGE)

        for path in ("/", "/a"):
            module_test.httpserver.expect_request(path).respond_with_handler(handler)

        async def inject():
            # an open port found while /a is held, so both its schemes are held behind /a
            await self.wait_until_held(module_test, HTTPSERVER_HOSTPORT)
            await self.inject(module_test, HTTPSERVER_HOSTPORT, event_type="OPEN_TCP_PORT")

        self.injector = asyncio.create_task(inject())

    def check(self, module_test, events):
        got = {e.parsed_url.path for e in events if e.type == "URL" and "status-200" in e.tags}
        assert got >= {"/", "/a"}, f"got {got}"
        limited = [t for t, _, status in self.requests if status == 429]
        gaps = [round(b - a, 2) for a, b in zip(limited, limited[1:])]
        assert all(g >= 0.8 for g in gaps), f"429s sent back to back while still limited: {gaps}"


class TestHTTP_429_held_url_keeps_its_retries(HTTP429Base):
    """A held URL whose connection drops is retried like any other (web.http_retries)."""

    targets = [f"{HTTPSERVER_URL}/a"]

    async def setup_after_prep(self, module_test):
        self.requests = 0

        def handler(request):
            self.requests += 1
            if self.requests == 1:
                return too_many()
            if self.requests == 2:
                # the drain's request: drop the connection without answering
                sock = request.environ["werkzeug.socket"]
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            return Response(OK_PAGE)

        module_test.httpserver.expect_request("/a").respond_with_handler(handler)

    def check(self, module_test, events):
        got = {e.parsed_url.path for e in events if e.type == "URL" and "status-200" in e.tags}
        assert "/a" in got, f"lost after one dropped connection; the server saw {self.requests} requests"
        assert self.requests == 3


CAP_PATHS = [f"/p{i}" for i in range(8)]


class TestHTTP_429_threads_cap(HTTP429Base):
    """`threads` caps the requests in flight across the batch and every drain together."""

    targets = [f"{base}{path}" for base in (HTTPSERVER_URL, LOCALHOST_URL) for path in CAP_PATHS]
    config_overrides = {
        "web": {"429_sleep_interval": 1, "429_max_sleep_interval": 1},
        "modules": {"http": {"threads": 2}},
    }
    deadline = 60
    limited_for = 2.5

    async def setup_after_prep(self, module_test):
        self.lock = threading.Lock()
        self.inflight = 0
        self.most = 0
        self.first = {}

        def handler(request):
            with self.lock:
                now = time.monotonic()
                # each hostname rate limits for longer than one retry would wait, so each gets a drain
                if now - self.first.setdefault(request.host, now) < self.limited_for:
                    return too_many()
                self.inflight += 1
                self.most = max(self.most, self.inflight)
            try:
                time.sleep(0.4)
                return Response(OK_PAGE)
            finally:
                with self.lock:
                    self.inflight -= 1

        for path in CAP_PATHS:
            module_test.httpserver.expect_request(path).respond_with_handler(handler)

    def check(self, module_test, events):
        got = {(e.parsed_url.netloc, e.parsed_url.path) for e in events if e.type == "URL" and "status-200" in e.tags}
        assert len(got) == 2 * len(CAP_PATHS), f"got {len(got)}"
        assert self.most <= 2, f"{self.most} requests in flight with threads=2"


class TestHTTP_429_prefetched(HTTP429Base):
    """
    A 429 the browser already fetched is held like one the module fetched, and fetched again once the host:port lets
    up, rather than reported as the page.
    """

    targets = [HTTPSERVER_URL]

    async def setup_after_prep(self, module_test):
        self.limited_requests = 0
        self.root_seen = False

        def limited(request):
            self.limited_requests += 1
            return too_many() if self.limited_requests == 1 else Response(OK_PAGE)

        def root(request):
            self.root_seen = True
            return Response(OK_PAGE)

        module_test.httpserver.expect_request("/limited").respond_with_handler(limited)
        module_test.httpserver.expect_request("/").respond_with_handler(root)

        # what the browser would have handed over: the page, answered with a 429
        self.prefetched = await blasthttp.BlastHTTP().request(f"{HTTPSERVER_URL}/limited", retry_statuses=[])
        assert self.prefetched.status == 429

        async def inject():
            await self.wait_for(lambda: self.root_seen)
            await self.inject(module_test, f"{HTTPSERVER_URL}/limited", prefetched_response=self.prefetched)

        self.injector = asyncio.create_task(inject())

    def check(self, module_test, events):
        urls = [e for e in events if e.type == "URL" and e.parsed_url.path == "/limited"]
        assert not any("status-429" in e.tags for e in urls), "the prefetched 429 was reported as the page"
        assert any("status-200" in e.tags for e in urls), "the held URL was never fetched again"
        assert self.limited_requests == 2


class TestHTTP_BrowserOnlyHost(ModuleTestBase):
    """The http module records a host as browser-only when it only answers with a browser challenge."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html>Just a moment...</html>",
            status=403,
            headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
        )

    def check(self, module_test, events):
        assert module_test.scan.helpers.web.is_browser_only("127.0.0.1")


class TestHTTP_BrowserFallback(ModuleTestBase):
    """With the browser enabled, a page behind a JavaScript challenge comes back as the real page."""

    pytestmark = pytest.mark.browser
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.cookies.get("cleared") != "1":
                challenge = (
                    "<html><head><title>Just a moment...</title></head><body><script>"
                    'document.cookie = "cleared=1; path=/"; setTimeout(() => location.reload(), 200);'
                    "</script></body></html>"
                )
                return Response(
                    challenge,
                    status=403,
                    headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
                    content_type="text/html",
                )
            return Response(
                "<html><head><title>real</title></head>past the challenge</html>", content_type="text/html"
            )

        module_test.httpserver.expect_request("/").respond_with_handler(handler)

    def check(self, module_test, events):
        responses = [e for e in events if e.type == "HTTP_RESPONSE"]
        assert any(e.data["status_code"] == 200 and "past the challenge" in e.body for e in responses)
        assert not any(e.data["status_code"] == 403 for e in responses)
        assert not module_test.scan.helpers.web.is_browser_only("127.0.0.1")
