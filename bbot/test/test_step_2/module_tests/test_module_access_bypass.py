import re
import json

from werkzeug.wrappers import Response

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL


class TestAccessBypass_path(ModuleTestBase):
    """Ported from bypass403: a single path mutation turns a 403 into a 200."""

    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/test..;/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1
        assert f"{HTTPSERVER_URL}/test..;/" in findings[0].data["description"]


class TestAccessBypass_collapse(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": "alive"}
        payloads = [
            "%09",
            "%20",
            "%23",
            "%2e",
            "%2f",
            ".",
            ";",
            "..;",
            "..;/",
            ";/",
            "/..;/",
            "/;/",
            "/./",
            "//",
            "/.",
        ]
        for qp in payloads:
            module_test.set_expect_requests(
                expect_args={"method": "GET", "uri": f"/test{qp}"}, respond_args=respond_args
            )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        # many signatures at once = unstable/catch-all host => suppressed entirely
        assert not [e for e in events if e.type == "FINDING"]


class TestAccessBypass_aspnetcookieless(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/admin.aspx"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": re.compile(r"\/\([sS]\(\w+\)\)\/.+\.aspx")}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert findings
        assert all("(S(X))/admin.aspx" in e.data["description"] for e in findings)


class TestAccessBypass_waf(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/test..;/"}
        respond_args = {"response_data": "The requested URL was rejected"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        assert not [e for e in events if e.type == "FINDING"]


class TestAccessBypass_extension_routing(ModuleTestBase):
    """Ported from url_manipulation: extension in a query param changes the 200 body."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "access_bypass"]
    module_name = "access_bypass"
    body = "<html><title>t</title><body><p>Hello null!</p></body></html>"
    body_match = "<html><title>t</title><body><p>Hello AAAAAAAAAAAAAA!</p></body></html>"

    async def setup_after_prep(self, module_test):
        rand_string = module_test.scan.modules["access_bypass"].rand_string
        module_test.set_expect_requests(
            expect_args={"query_string": f"{rand_string}=.xml".encode()},
            respond_args={"response_data": self.body_match},
        )
        module_test.set_expect_requests(respond_args={"response_data": self.body})

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and "URL Manipulation" in e.data["description"] and "=.xml" in e.data["description"]
            for e in events
        )


class TestAccessBypass_xff(ModuleTestBase):
    """T1.1: an IP-spoofing header turns a 406 into a 200."""

    targets = [f"{HTTPSERVER_URL}/secret"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP"):
                return Response("secret content unlocked", status=200)
            return Response("", status=406)

        module_test.httpserver.expect_request("/secret").respond_with_handler(handler)
        module_test.httpserver.no_handler_status_code = 406

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert findings
        assert any("Added Header" in f.data["description"] for f in findings)


class TestAccessBypass_bearer(ModuleTestBase):
    """T1.2: a garbage Bearer token turns a 401 into a 200."""

    targets = [f"{HTTPSERVER_URL}/api/data"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.headers.get("Authorization", "").startswith("Bearer "):
                return Response('{"data": "sensitive"}', status=200)
            return Response("unauthorized", status=401)

        module_test.httpserver.expect_request("/api/data").respond_with_handler(handler)
        module_test.httpserver.no_handler_status_code = 401

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any("Authentication Bypass" in f.data["description"] for f in findings)


class TestAccessBypass_apigw(ModuleTestBase):
    """T1.6: Authorization: deny reaches the backend, proven by x-amzn-remapped-* headers."""

    targets = [f"{HTTPSERVER_URL}/stage/resource"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            auth = request.headers.get("Authorization", "")
            if auth == "deny":
                return Response(
                    "backend reached",
                    status=200,
                    headers={"x-amzn-remapped-content-length": "15", "x-amzn-requestid": "abc"},
                )
            return Response(
                '{"message":"Unauthorized"}',
                status=401,
                headers={"x-amzn-requestid": "abc", "x-amzn-errortype": "UnauthorizedException"},
            )

        module_test.httpserver.expect_request("/stage/resource").respond_with_handler(handler)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any("API Gateway" in f.data["description"] for f in findings)


class TestAccessBypass_extension_append(ModuleTestBase):
    """T1.4: appending .js to a blocked path reaches the app (and is not a real static file)."""

    targets = [f"{HTTPSERVER_URL}/admin"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/admin.js"},
            respond_args={"response_data": '{"app":"data"}', "headers": {"Content-Type": "application/json"}},
        )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any(f"{HTTPSERVER_URL}/admin.js" in f.data["description"] for f in findings)


class TestAccessBypass_double_slash(ModuleTestBase):
    """T1.3: a per-segment double slash reaches the origin un-normalized."""

    targets = [f"{HTTPSERVER_URL}/api/v2"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/api//v2"}, respond_args={"response_data": "origin reached"}
        )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any(f"{HTTPSERVER_URL}/api//v2" in f.data["description"] for f in findings)


class TestAccessBypass_semicolon(ModuleTestBase):
    """T1.5: a semicolon matrix-param breaks an edge deny-list but the origin resolves the path."""

    targets = [f"{HTTPSERVER_URL}/env"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/env;x=.ico"}, respond_args={"response_data": "secret config"}
        )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any("env;x=.ico" in f.data["description"] for f in findings)


class TestAccessBypass_extension_append_realfile(ModuleTestBase):
    """T1.4 negative: appending .png returns a genuine image, so it is not a bypass."""

    targets = [f"{HTTPSERVER_URL}/admin"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/admin.png"},
            respond_args={"response_data": png, "headers": {"Content-Type": "image/png"}},
        )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any("admin.png" in f.data["description"] for f in findings)


class TestAccessBypass_catchall(ModuleTestBase):
    """A blocked target whose every other path 200s (with the path reflected into the body,
    so bodies are all unique) must still be recognized as a catch-all and produce nothing."""

    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.path == "/test":
                return Response("", status=403)
            # reflect the path so every junk response is byte-different (defeats a naive body diff)
            return Response(f"welcome, you asked for {request.path}", status=200)

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any("Path Manipulation" in f.data["description"] for f in findings), (
            f"catch-all host produced path findings: {[f.data['description'] for f in findings]}"
        )


class TestAccessBypass_5xx_not_bypass(ModuleTestBase):
    """Regression for a Cloudflare+Spring host: blocked baseline, malformed paths 500 (echoing the
    path). A 5xx is not a bypass, and the reflected-path 500s must not each count as a signature."""

    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.path == "/test":
                return Response("", status=401)
            return Response(
                json.dumps({"status": 500, "error": "Internal Server Error", "path": request.path}),
                status=500,
                headers={"Content-Type": "application/json"},
            )

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        assert not [e for e in events if e.type == "FINDING"]


class TestAccessBypass_apigw_negative(ModuleTestBase):
    """T1.6 negative: no x-amzn-remapped-* means the gateway answered, not the backend."""

    targets = [f"{HTTPSERVER_URL}/stage/resource"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.headers.get("Authorization") == "deny":
                return Response(
                    '{"message":"Access Denied"}',
                    status=403,
                    headers={"x-amzn-requestid": "abc", "x-amzn-errortype": "AccessDeniedException"},
                )
            return Response(
                '{"message":"Unauthorized"}',
                status=401,
                headers={"x-amzn-requestid": "abc", "x-amzn-errortype": "UnauthorizedException"},
            )

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any("API Gateway" in f.data["description"] for f in findings)


class TestAccessBypass_nextjs_redirected(ModuleTestBase):
    """T2.2 negative: the data route is also redirected, so it is not a bypass."""

    targets = [f"{HTTPSERVER_URL}/internal/article"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    build_id = "oK8YOQsGEZuc7QTm"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/internal/article"},
            respond_args={"response_data": "", "status": 302, "headers": {"Location": "/auth/signin"}},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": f'<script id="__NEXT_DATA__">{{"buildId":"{self.build_id}"}}</script>'},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": f"/_next/data/{self.build_id}/internal/article.json"},
            respond_args={
                "response_data": json.dumps({"pageProps": {"__N_REDIRECT": "/auth/signin"}}),
                "headers": {"Content-Type": "application/json"},
            },
        )
        module_test.httpserver.no_handler_status_code = 404

    def check(self, module_test, events):
        assert not any(e.type == "FINDING" and "Next.js" in e.data["description"] for e in events)


class TestAccessBypass_nextjs(ModuleTestBase):
    """T2.2: a page that redirects to /auth/signin is reachable via its _next/data route."""

    targets = [f"{HTTPSERVER_URL}/internal/article"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    build_id = "oK8YOQsGEZuc7QTm"

    async def setup_after_prep(self, module_test):
        # the protected page redirects to the auth gate
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/internal/article"},
            respond_args={"response_data": "", "status": 302, "headers": {"Location": "/auth/signin"}},
        )
        # the host root leaks the buildId
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": f'<script id="__NEXT_DATA__">{{"buildId":"{self.build_id}"}}</script>'},
        )
        # the data route returns the protected page data unauthenticated
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": f"/_next/data/{self.build_id}/internal/article.json"},
            respond_args={
                "response_data": json.dumps({"pageProps": {"secret": "internal content"}}),
                "headers": {"Content-Type": "application/json"},
            },
        )
        module_test.httpserver.no_handler_status_code = 404

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any("Next.js" in f.data["description"] for f in findings)
