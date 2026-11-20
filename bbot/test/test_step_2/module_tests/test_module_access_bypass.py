import re
import json
import itertools

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


class TestAccessBypass_extension_routing_page_changes(ModuleTestBase):
    """A page that changes partway through the probes changes without the extension too, so it isn't routing"""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "access_bypass"]
    module_name = "access_bypass"
    body = "<html><title>t</title><body><p>Hello null!</p></body></html>"
    body_changed = "<html><title>t</title><body><p>Hello AAAAAAAAAAAAAA!</p></body></html>"

    async def setup_after_prep(self, module_test):
        rand_string = module_test.scan.modules["access_bypass"].rand_string
        changed = []

        def handler(request):
            if request.query_string.decode() == f"{rand_string}=.jpg":
                changed.append(True)
            return Response(self.body_changed if changed else self.body, content_type="text/html")

        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=handler)

    def check(self, module_test, events):
        assert not [e for e in events if e.type == "FINDING"]


class TestAccessBypass_block_lifts(ModuleTestBase):
    """A block that lifts partway through makes the URL itself answer, so what got through then isn't a bypass"""

    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    config_overrides = {"modules": {"access_bypass": {"enabled_submodules": ["path"]}}}

    async def setup_after_prep(self, module_test):
        lifted = []

        def bypass(request):
            lifted.append(True)
            return Response("alive")

        def page(request):
            # the URL itself, not the mutations of it that also land here
            if lifted and request.environ.get("REQUEST_URI") == "/test":
                return Response("public page")
            return Response("blocked", status=403)

        module_test.set_expect_requests_handler(expect_args="/test..;/", request_handler=bypass)
        module_test.set_expect_requests_handler(expect_args="/test", request_handler=page)
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        assert not [e for e in events if e.type == "FINDING"]


class TestAccessBypass_block_changes(TestAccessBypass_block_lifts):
    """A block that gives way to another answer partway through, like a rate limit to the site's own error, wasn't the
    site's answer, so what got through then isn't a bypass"""

    async def setup_after_prep(self, module_test):
        changed = []

        def bypass(request):
            changed.append(True)
            return Response("alive")

        def page(request):
            if changed and request.environ.get("REQUEST_URI") == "/test":
                return Response("unprocessable", status=422)
            return Response("blocked", status=403)

        module_test.set_expect_requests_handler(expect_args="/test..;/", request_handler=bypass)
        module_test.set_expect_requests_handler(expect_args="/test", request_handler=page)
        module_test.httpserver.no_handler_status_code = 403


class TestAccessBypass_unstable_control(ModuleTestBase):
    """A probe whose control paths aren't answered alike can't be told from a catch-all, so it isn't reported"""

    targets = [f"{HTTPSERVER_URL}/test"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    config_overrides = {"modules": {"access_bypass": {"enabled_submodules": ["path"]}}}

    async def setup_after_prep(self, module_test):
        # the made-up control paths get a page and a not-found in turn, so the control's two samples disagree
        control_answers = itertools.cycle([200, 404])

        def handler(request):
            uri = request.environ.get("REQUEST_URI")
            if uri == "/test..;/":
                return Response("alive")
            # every other mutation of /test, case-swapped too, so only the control's two requests take turns below
            if "test" in uri.lower():
                return Response("blocked", status=403)
            status = next(control_answers)
            return Response("a page" if status == 200 else "not found", status=status)

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e.data["description"] for e in events if e.type == "FINDING"]
        assert not findings, findings


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


class TestAccessBypass_method(ModuleTestBase):
    """A GET-only block is lifted when the same path is replayed as POST (state_changing enabled)."""

    targets = [f"{HTTPSERVER_URL}/secure"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    config_overrides = {"modules": {"access_bypass": {"state_changing_methods": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/secure", method="POST").respond_with_data(
            "admin area reached", status=200
        )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any("Modified Method: POST" in f.data["description"] for f in findings)


class TestAccessBypass_method_gated(ModuleTestBase):
    """With the default config, state-changing verbs are not sent, so a POST-only bypass is missed."""

    targets = [f"{HTTPSERVER_URL}/secure"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/secure", method="POST").respond_with_data(
            "admin area reached", status=200
        )
        module_test.httpserver.no_handler_status_code = 403

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any("Modified Method" in f.data["description"] for f in findings)


class TestAccessBypass_method_options_catchall(ModuleTestBase):
    """A server that answers OPTIONS 200 for every path is not a bypass (catch-all)."""

    targets = [f"{HTTPSERVER_URL}/secure"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.method == "OPTIONS":
                return Response("", status=200)
            return Response("", status=403)

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any("Modified Method: OPTIONS" in f.data["description"] for f in findings)


class TestAccessBypass_method_options_no_content(ModuleTestBase):
    """OPTIONS answering 200 on the blocked path only, with no content, is not a bypass."""

    targets = [f"{HTTPSERVER_URL}/secure"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    options_body = ""

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.method == "OPTIONS":
                if request.path == "/secure":
                    return Response(self.options_body, status=200, headers={"Allow": "GET,HEAD,POST"})
                return Response("not found", status=404)
            return Response("access denied", status=403)

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert not any("Method Manipulation" in f.data["description"] for f in findings), (
            f"OPTIONS without content produced a finding: {[f.data['description'] for f in findings]}"
        )


class TestAccessBypass_method_options_method_list(TestAccessBypass_method_options_no_content):
    """An OPTIONS body that only lists the allowed methods is not content."""

    options_body = "GET,HEAD,POST"


class TestAccessBypass_method_unknown_verb(ModuleTestBase):
    """An unknown verb routed to the real page is a bypass, shown next to the blocked response."""

    targets = [f"{HTTPSERVER_URL}/secure"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            if request.method == "ACB" and request.path == "/secure":
                return Response("<html><title>Admin Panel</title>admin area reached</html>", status=200)
            if request.method == "ACB":
                return Response("not found", status=404)
            return Response("access denied", status=403)

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and "Method Manipulation" in e.data["description"]]
        assert len(findings) == 1
        assert findings[0].data["description"] == (
            "Method Manipulation. Signature: [Modified Method: ACB] Baseline: [403, 13 bytes] -> "
            "Probe: [200, 57 bytes, 'Admin Panel'] Differences: [code,body]"
        )


class TestAccessBypass_encoded_qmark(ModuleTestBase):
    """Family 1: /admin%3F truncates at the origin to /admin, bypassing the block on /admin."""

    targets = [f"{HTTPSERVER_URL}/admin"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"

    async def setup_after_prep(self, module_test):
        def handler(request):
            raw = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI") or ""
            if "%3f" in raw.lower():
                # origin truncates at the (decoded) '?', routing by what's left of it
                truncated = re.split(r"%3[fF]", raw)[0].rstrip("/")
                if truncated == "/admin":
                    return Response("admin content reached", status=200)
                return Response("", status=404)
            # direct access is blocked
            return Response("", status=403)

        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert any("/admin%3F" in f.data["description"] for f in findings)


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


# a folder of static files on a CDN, closed to listing, in front of an app that answers any other path with its own page
STATIC_DENIED = "<Error><Code>AccessDenied</Code></Error>"
APP_PAGE = "<html><head><title>Home</title></head><body>the app, build {build}</body></html>"


def catch_all(changes_once=None, secret_uris=()):
    """
    A handler for that site. The page at `changes_once` comes back from another build on its second request only, like a
    page caught mid-deploy. `secret_uris` get the folder's own content.
    """
    requests = {}

    def handler(request):
        uri = request.environ.get("REQUEST_URI")
        if uri in secret_uris:
            return Response("the static folder's index: app.js, config.json")
        if uri.startswith("/static/"):
            return Response(STATIC_DENIED, status=403)
        requests[uri] = requests.get(uri, 0) + 1
        build = 2 if uri == changes_once and requests[uri] == 2 else 1
        return Response(APP_PAGE.format(build=build))

    return handler


class TestAccessBypass_catch_all_changed_once(ModuleTestBase):
    """A probe that gets the site's catch-all page isn't a bypass, even if the page changed between it and the control"""

    targets = [f"{HTTPSERVER_URL}/static/app/"]
    modules_overrides = ["access_bypass", "http"]
    module_name = "access_bypass"
    config_overrides = {"modules": {"access_bypass": {"enabled_submodules": ["path"]}}}

    async def setup_after_prep(self, module_test):
        handler = catch_all(changes_once="/%2e/static/app/")
        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e.data["description"] for e in events if e.type == "FINDING" and e.data["severity"] == "MEDIUM"]
        assert not findings, findings


class TestAccessBypass_catch_all_real_bypass(TestAccessBypass_catch_all_changed_once):
    """On the same site, a probe that gets the folder's own content is still a bypass"""

    async def setup_after_prep(self, module_test):
        handler = catch_all(secret_uris={"/static/app..;/"})
        module_test.httpserver.expect_request(re.compile(r"/.*")).respond_with_handler(handler)

    def check(self, module_test, events):
        findings = [e.data["description"] for e in events if e.type == "FINDING" and e.data["severity"] == "MEDIUM"]
        assert len(findings) == 1, findings
        assert f"{HTTPSERVER_URL}/static/app..;/" in findings[0]
