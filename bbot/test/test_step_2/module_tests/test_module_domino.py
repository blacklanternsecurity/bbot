import asyncio
import html
import re
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from werkzeug.wrappers import Response

from .base import ModuleTestBase
from bbot.modules.base import BaseModule
from bbot.test.worker import HTTPSERVER_URL

# writes the URL fragment into the page as HTML
VULNERABLE_PAGE = """<html><head><title>domino test</title></head><body>
<p>The hash is: <span id="output"></span></p>
<script>
document.getElementById("output").innerHTML = decodeURIComponent(location.hash.substring(1));
</script>
</body></html>"""

CLEAN_PAGE = """<html><head><title>domino test</title></head><body>
<p>The hash is: <span id="output"></span></p>
<script>
document.getElementById("output").textContent = decodeURIComponent(location.hash.substring(1));
</script>
</body></html>"""


class TestDomino(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/other", f"{HTTPSERVER_URL}/clean"]
    modules_overrides = ["http", "domino"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"domino": {"rules": ["xss-basic"]}}}

    async def setup_after_prep(self, module_test):
        pages = {
            "/": VULNERABLE_PAGE,
            "/same": VULNERABLE_PAGE,
            # the same code in a different page
            "/other": VULNERABLE_PAGE.replace("The hash is", "Here is the hash"),
            "/clean": CLEAN_PAGE,
        }
        for uri, page in pages.items():
            module_test.set_expect_requests({"uri": uri}, {"response_data": page, "content_type": "text/html"})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1
        finding = findings[0].data
        assert finding["name"] == "Dom-Based XSS"
        assert finding["severity"] == "HIGH"
        assert finding["confidence"] == "CONFIRMED"
        assert finding["url"].split("#")[0] in (
            f"{HTTPSERVER_URL}/",
            f"{HTTPSERVER_URL}/same",
            f"{HTTPSERVER_URL}/other",
        )
        assert "alert() containing 'AAABBB' was executed" in finding["description"]

        # pages running the same code are scanned once, so only one of the three vulnerable pages was
        probed = {request.path for request, _ in module_test.httpserver.log if request.query_string}
        assert len(probed & {"/", "/same", "/other"}) == 1
        assert "/clean" in probed
        # "/same" has the same body as "/", so it never gets this far; "/other" does, and is skipped
        module = module_test.scan.modules["domino"]
        assert module.pages_seen == 3
        assert len(module.analyzed) == 2


class TestDominoTimeBudget(ModuleTestBase):
    """DOMino stops when it runs out of time, and the module reports what it found before then"""

    pytestmark = pytest.mark.browser
    module_name = "domino"
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["xss-basic"], "time_budget": 30}},
    }

    async def setup_after_prep(self, module_test):
        from domino.lib import inputs

        module_test.set_expect_requests({"uri": "/"}, {"response_data": VULNERABLE_PAGE, "content_type": "text/html"})
        load = inputs.Hash.load

        # xss-basic's last input never finishes loading, after the hash payload before it found the XSS
        async def stuck_svg_payload(self, page=None, referer=None):
            if "svg" in self.param_value:
                await asyncio.Event().wait()
            return await load(self, page, referer)

        module_test.monkeypatch.setattr(inputs.Hash, "load", stuck_svg_payload)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert [finding.data["name"] for finding in findings] == ["Dom-Based XSS"]


class TestDominoOneLine(ModuleTestBase):
    """A finding's description is one line, however many lines DOMino's details and interactions span"""

    pytestmark = pytest.mark.browser
    module_name = "domino"
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"domino": {"rules": ["xss-basic"]}}}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": VULNERABLE_PAGE, "content_type": "text/html"})

        async def multi_line_results(url, parameters=None):
            return [
                {
                    "rule_name": "Dom-Based XSS",
                    "description": "Detects confirmed execution\nfrom DOM XSS payloads",
                    "severity": "high",
                    "details": ["JavaScript alert()\n    was executed"],
                    "interactions": ['Clicked element: <form id="f">\n    <input name="q">\n</form>'],
                    "detection_url": f"{HTTPSERVER_URL}/?q=x",
                }
            ], True

        module_test.monkeypatch.setattr(module_test.scan.modules["domino"], "run_domino", multi_line_results)

    def check(self, module_test, events):
        findings = [e.data for e in events if e.type == "FINDING"]
        assert len(findings) == 1
        description = findings[0]["description"]
        assert "\n" not in description
        assert 'Interactions: [Clicked element: <form id="f"> <input name="q"> </form>]' in description


class TestDominoConfidence(TestDominoOneLine):
    """A finding's confidence is DOMino's, and confirmed when DOMino doesn't give one"""

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": VULNERABLE_PAGE, "content_type": "text/html"})

        async def results(url, parameters=None):
            return [
                {"rule_name": "Dom-Based XSS", "description": "Detects confirmed execution", "severity": "high"},
                {
                    "rule_name": "Client-Side Path Traversal to XSS",
                    "description": "Detects input that picks the path of a request",
                    "severity": "medium",
                    "confidence": "medium",
                },
            ], True

        module_test.monkeypatch.setattr(module_test.scan.modules["domino"], "run_domino", results)

    def check(self, module_test, events):
        confidence = {e.data["name"]: e.data["confidence"] for e in events if e.type == "FINDING"}
        assert confidence == {"Dom-Based XSS": "CONFIRMED", "Client-Side Path Traversal to XSS": "MEDIUM"}


class TestDominoOutOfTime(ModuleTestBase):
    """A parameter DOMino discovered but ran out of time to test is handed on, and tested in a run of its own"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["get-parameter-discovery", "xss-onclick-getparam"], "web_parameters": True}},
    }
    # the parameters each DOMino run was given
    runs = []

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": VULNERABLE_PAGE, "content_type": "text/html"})

        async def run_domino(url, parameters=None):
            self.runs.append(parameters)
            if parameters:
                return [], True
            discovery = {
                "rule_name": "GET Parameter Access",
                "description": "Detects attempts to access GET parameters",
                "severity": "info",
                "value_found": "next",
            }
            return [discovery], False

        module_test.monkeypatch.setattr(module_test.scan.modules["domino"], "run_domino", run_domino)

    def check(self, module_test, events):
        parameters = [e.data for e in events if e.type == "WEB_PARAMETER" and str(e.module) == "domino"]
        assert [p["name"] for p in parameters] == ["next"], parameters
        assert self.runs == [None, ["next"]], self.runs


class TestDominoPageShare(ModuleTestBase):
    """DOMino's runs at once share the browser's pages, less the one left for everything else, rather than each taking them all"""

    pytestmark = pytest.mark.browser
    module_name = "domino"
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {
        "web": {"enable_browser": True, "browser_max_pages": 8},
        "modules": {"domino": {"rules": ["xss-basic"], "module_threads": 2}},
    }
    # the page concurrency each run is given, for this many pages and runs at once
    expected = 3

    async def setup_after_prep(self, module_test):
        module_test.domino_options = []

        class Domino:
            def __init__(self, url, **options):
                module_test.domino_options.append(options)
                self.ran_out_of_time = False

            async def run(self, browser):
                return []

        module = module_test.scan.modules["domino"]
        module_test.monkeypatch.setitem(type(module).run_domino.__globals__, "Domino", Domino)

    async def check(self, module_test, events):
        module_test.domino_options.clear()
        await module_test.scan.modules["domino"].run_domino(f"{HTTPSERVER_URL}/")
        assert [options["max_concurrency"] for options in module_test.domino_options] == [self.expected]


class TestDominoPageShareOneRun(TestDominoPageShare):
    """One run at a time takes every page but the one left for everything else, as before"""

    config_overrides = {
        "web": {"enable_browser": True, "browser_max_pages": 8},
        "modules": {"domino": {"rules": ["xss-basic"]}},
    }
    expected = 7


class TestDominoPrecheck(ModuleTestBase):
    """Parameters DOMino can't use are turned away before they're queued: POST parameters, endpoints that aren't
    pages, and names paramminer found only by how the server answered, without echoing them"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["domino"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"domino": {"web_parameters": True}}}

    async def setup_after_prep(self, module_test):
        class paramminer_getparams(BaseModule):
            _name = "paramminer_getparams"

        scan = module_test.scan
        paramminer = paramminer_getparams(scan)

        def parameter(name, type="GETPARAM", module=None, tags=None, **data):
            return scan.make_event(
                {
                    "host": "127.0.0.1",
                    "url": f"{HTTPSERVER_URL}/",
                    "type": type,
                    "name": name,
                    "description": "",
                    **data,
                },
                "WEB_PARAMETER",
                parent=scan.root_event,
                module=module,
                tags=tags,
            )

        self.verdicts = {
            name: module_test.scan.modules["domino"]._event_precheck(event)[0]
            for name, event in (
                ("found in a link", parameter("q")),
                ("posted", parameter("p", type="POSTPARAM")),
                ("json endpoint", parameter("j", content_type="application/json")),
                ("guessed", parameter("debug", module=paramminer)),
                ("guessed and echoed", parameter("next", module=paramminer, tags=["http_reflection"])),
            )
        }

    def check(self, module_test, events):
        assert self.verdicts == {
            "found in a link": True,
            "posted": False,
            "json endpoint": False,
            "guessed": False,
            "guessed and echoed": True,
        }


class TestDominoSharedFingerprint(ModuleTestBase):
    """A page whose code fingerprint another module already worked out isn't loaded again just to learn it"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"domino": {"rules": ["xss-basic"]}}}
    runs = []
    loads = []

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": VULNERABLE_PAGE, "content_type": "text/html"})
        module = module_test.scan.modules["domino"]
        # as codeql leaves it for a page it analyzed
        module_test.scan.helpers.browser.code_fingerprints[f"{HTTPSERVER_URL}/"] = "fingerprint from another module"

        async def page_code(event):
            self.loads.append(event.url)

        async def run_domino(url, parameters=None):
            self.runs.append(url)
            return [], True

        module_test.monkeypatch.setattr(module, "page_code", page_code)
        module_test.monkeypatch.setattr(module, "run_domino", run_domino)

    def check(self, module_test, events):
        assert self.runs == [f"{HTTPSERVER_URL}/"], self.runs
        assert self.loads == [], self.loads


# two pages running the same code, each linked with the same parameter
LINKS_PAGE = (
    """<html><head><title>links</title></head><body><a href="/a?q=1">a</a><a href="/b?q=1">b</a></body></html>"""
)
SAME_CODE_PAGE = """<html><head><title>same code</title></head><body><script>
document.title = new URLSearchParams(location.search).get("q");
</script></body></html>"""


class TestDominoParameterOncePerCode(ModuleTestBase):
    """A parameter is tested once on a host for each page code, not once for every page running that code"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {
        "excavate": True,
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["xss-onclick-getparam"], "web_parameters": True}},
    }
    # the parameters each DOMino run was given
    runs = []

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": LINKS_PAGE, "content_type": "text/html"})
        for uri in ("/a", "/b"):
            module_test.set_expect_requests(
                {"uri": uri}, {"response_data": SAME_CODE_PAGE, "content_type": "text/html"}
            )

        async def run_domino(url, parameters=None):
            self.runs.append(parameters)
            return [], True

        module_test.monkeypatch.setattr(module_test.scan.modules["domino"], "run_domino", run_domino)

    def check(self, module_test, events):
        parameters = [e.data["url"] for e in events if e.type == "WEB_PARAMETER" and e.data["name"] == "q"]
        # both pages were handed q, but it was tested once
        assert {f"{HTTPSERVER_URL}/a", f"{HTTPSERVER_URL}/b"} <= set(parameters), parameters
        assert [run for run in self.runs if run] == [["q"]], self.runs


# links to two requests of one page: one with three parameters, one with another
PARAMETERS_PAGE = """<html><head><title>links</title></head><body>
<a href="/page?a=1&b=2&c=3">page</a><a href="/page?d=4">other</a></body></html>"""


class TestDominoParameterBatch(ModuleTestBase):
    """The GET parameters of one request are tested in one DOMino run of that request, never mixed with another
    request's; the page is loaded at most once to find its code, and each finding goes under the parameter it's about"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {
        "excavate": True,
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["xss-onclick-getparam"], "web_parameters": True}},
    }
    # (url, parameters) of each DOMino run given parameters, and each URL loaded to find a parameter's page code
    runs = []
    loaded = []

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": PARAMETERS_PAGE, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/page"}, {"response_data": SAME_CODE_PAGE, "content_type": "text/html"}
        )
        module = module_test.scan.modules["domino"]

        async def run_domino(url, parameters=None):
            if not parameters:
                # a page's run takes a while, so the parameters it links to queue up behind it, into one batch
                await asyncio.sleep(2)
                return [], True
            self.runs.append((url, parameters))
            if "b" not in parameters:
                return [], True
            # a finding for b, as DOMino reports one: at the URL tested, with b's value changed
            return [
                {
                    "rule_name": "Dom-Based XSS Via Click() Events from GET parameter",
                    "description": "Detects XSS",
                    "severity": "high",
                    "detection_url": url.replace("b=2", "b=PAYLOAD"),
                }
            ], True

        url_code = module.url_code

        async def counting_url_code(url):
            self.loaded.append(url)
            return await url_code(url)

        module_test.monkeypatch.setattr(module, "run_domino", run_domino)
        module_test.monkeypatch.setattr(module, "url_code", counting_url_code)

    def check(self, module_test, events):
        runs = {tuple(parameters): parse_qs(urlparse(url).query) for url, parameters in self.runs}
        # each request tested as it was found, the parameters of one never added to the other
        assert runs == {("a", "b", "c"): {"a": ["1"], "b": ["2"], "c": ["3"]}, ("d",): {"d": ["4"]}}, self.runs
        assert len([u for u in self.loaded if "/page" in u]) <= 1, self.loaded
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1, findings
        assert findings[0].parent.type == "WEB_PARAMETER" and findings[0].parent.data["name"] == "b"


# a search whose results page fetches the results and evals them, which the server writes with " escaped but not \\
SEARCH_JS = """function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var results = ' + this.responseText);
            document.getElementById('term').innerText = results.searchTerm;
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();
}"""

SEARCH_FORM = """<form action=/ method=GET><input type=text name=search><button type=submit>Search</button></form>"""


def search_handler(request):
    query = parse_qs(request.query_string.decode(), keep_blank_values=True)
    if request.path == "/search.js":
        return Response(SEARCH_JS, content_type="application/javascript")
    if request.path == "/search-results":
        term = query.get("search", [""])[0].replace('"', '\\"')
        return Response('{"searchTerm":"' + term + '"}', content_type="application/json")
    page = "<html><head><title>search</title></head><body>"
    if "search" in query:
        page += "<span id=term></span><script src='/search.js'></script><script>search('search-results')</script>"
    return Response(page + SEARCH_FORM + "</body></html>", content_type="text/html")


class TestDominoWebParameters(ModuleTestBase):
    """With web_parameters, a GET parameter excavate finds in a form is tested by name"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    # neither rule's own made-up parameters reach the code that evals the results
    config_overrides = {
        "excavate": True,
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["eval", "xss-js"], "web_parameters": True}},
    }

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=search_handler)

    def check(self, module_test, events):
        assert module_test.scan.modules["excavate"].parameter_extraction
        findings = {e.data["name"]: e.data for e in events if e.type == "FINDING"}
        assert "User Input in Eval()" in findings
        breakout = findings["Dom-Based XSS via direct Javascript"]
        assert breakout["severity"] == "HIGH"
        assert "AAAFFF" in breakout["description"]
        # a FINDING's url loses its query, so the parameter shows in the detection URL in its description
        assert "Detection URL: [http://127.0.0.1" in breakout["description"]
        assert "/?search=" in breakout["description"]


class TestDominoWebParametersOff(TestDominoWebParameters):
    """Without web_parameters, domino doesn't turn on parameter extraction, and the parameter goes untested"""

    config_overrides = {
        "excavate": True,
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["eval", "xss-js"]}},
    }

    def check(self, module_test, events):
        assert not module_test.scan.modules["excavate"].parameter_extraction
        assert not [e for e in events if e.type in ("FINDING", "WEB_PARAMETER")]


# what /connect kept of each request, by the state it redirected with
CONNECT_STATES = {}


def connect_handler(request):
    """
    /start sends the browser to /connect with a client and an include URL; /connect, which answers only its client,
    keeps the include URL under a new state and sends the browser to /page, which loads a script from it
    """
    query = {name: values[0] for name, values in parse_qs(request.query_string.decode()).items()}
    if request.path == "/start":
        return Response("", status=302, headers={"Location": f"/connect?client=c1ient&include={HTTPSERVER_URL}"})
    if request.path == "/connect":
        if query.get("client") != "c1ient":
            return Response("<html><body>unknown client</body></html>", status=400, content_type="text/html")
        state = secrets.token_hex(8)
        CONNECT_STATES[state] = query.get("include", "")
        return Response("", status=302, headers={"Location": f"/page?state={state}"})
    include = CONNECT_STATES.get(query.get("state"))
    script = f'<script src="{html.escape(include, quote=True)}/app.js"></script>' if include else ""
    return Response(f"<html><head><title>sign in</title>{script}</head><body></body></html>", content_type="text/html")


class TestDominoParameterSiblings(ModuleTestBase):
    """A GET parameter is tested in the request it was found in, with the parameters that came with it"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/start"]
    modules_overrides = ["http", "domino"]
    config_overrides = {
        "excavate": True,
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["remote-include-get-parameters"], "web_parameters": True}},
    }

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=connect_handler)

    def check(self, module_test, events):
        findings = [e.data for e in events if e.type == "FINDING"]
        assert [f["name"] for f in findings] == ["Remote Javascript Include (Discovered GET Parameters)"], findings
        # reported at the request that reproduces it, not the page it redirected to
        assert "Detection URL: [http://127.0.0.1" in findings[0]["description"]
        assert "/connect?" in findings[0]["description"]
        assert "client=c1ient" in findings[0]["description"]


# a page whose script calls a JSON API and a results page, each with a parameter
FETCHING_PAGE = """<html><head><title>fetching</title></head><body><script>
fetch("/api/items?q=books");
fetch("/results?search=books");
</script></body></html>"""


class TestDominoBrowserParameters(ModuleTestBase):
    """Of the parameters a page's scripts send, DOMino tests the ones whose endpoint answered with a page"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "browser_dom", "domino"]
    config_overrides = {
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["get-parameter-reflection"], "web_parameters": True}},
    }

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": FETCHING_PAGE, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/api/items"}, {"response_data": '{"items": []}', "content_type": "application/json"}
        )
        module_test.set_expect_requests(
            {"uri": "/results"}, {"response_data": "<html><body>results</body></html>", "content_type": "text/html"}
        )

    def check(self, module_test, events):
        captured = {e.data["name"] for e in events if e.type == "WEB_PARAMETER" and str(e.module) == "browser_dom"}
        assert {"q", "search"} <= captured
        tested = {name for _, _, name in module_test.scan.modules["domino"].tested_parameters}
        assert "search" in tested
        assert "q" not in tested, "DOMino loaded a JSON API's parameter as a page"


# what a challenge answers instead of the site: it writes the whole query into the page, so anything tested on it is found
CHALLENGE_PAGE = """<html><head><title>Just a moment...</title></head><body><span id="out"></span><script>
document.getElementById("out").innerHTML = decodeURIComponent(location.search);
</script></body></html>"""


def challenge_handler(request):
    """The site's page, with a form taking q, answered with a Cloudflare-style challenge whenever q has a value"""
    query = parse_qs(request.query_string.decode(), keep_blank_values=True)
    if query.get("q", [""])[0]:
        return Response(
            CHALLENGE_PAGE,
            status=403,
            headers={"Server": "cloudflare", "cf-mitigated": "challenge"},
            content_type="text/html",
        )
    form = "<form action=/ method=GET><input type=text name=q><button type=submit>Go</button></form>"
    return Response(VULNERABLE_PAGE.replace("</body>", f"{form}</body>"), content_type="text/html")


class TestDominoChallenge(ModuleTestBase):
    """A page DOMino loads that a bot challenge answers instead of the site isn't tested, while the site's own pages are"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "domino"]
    config_overrides = {
        "excavate": True,
        "web": {"enable_browser": True},
        "modules": {"domino": {"rules": ["xss-basic"], "web_parameters": True}},
    }

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests_handler(expect_args=re.compile("/.*"), request_handler=challenge_handler)

    @staticmethod
    def found_on_q(events):
        return [e for e in events if e.type == "FINDING" and "?q=" in e.data["description"]]

    def check(self, module_test, events):
        # DOMino loaded q's tests, and the challenge answered them
        challenged = [
            request
            for request, _ in module_test.httpserver.log
            if parse_qs(request.query_string.decode()).get("q", [""])[0]
        ]
        assert challenged
        assert not self.found_on_q(events), [e.data["description"] for e in self.found_on_q(events)]
        findings = [e.data for e in events if e.type == "FINDING"]
        assert any(f["name"] == "Dom-Based XSS" and "#" in f["description"] for f in findings), findings


class TestDominoChallengeUnchecked(TestDominoChallenge):
    """Without the check, the challenge's page is tested like the site's, and what it echoes is reported"""

    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)

        async def never_blocked(response):
            return None

        module_test.scan.helpers.browser.blocked_by = never_blocked

    def check(self, module_test, events):
        assert self.found_on_q(events)
