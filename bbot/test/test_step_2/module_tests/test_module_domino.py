import asyncio
import html
import re
import secrets
from urllib.parse import parse_qs

import pytest
from werkzeug.wrappers import Response

from .base import ModuleTestBase
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
            ]

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
            ]

        module_test.monkeypatch.setattr(module_test.scan.modules["domino"], "run_domino", results)

    def check(self, module_test, events):
        confidence = {e.data["name"]: e.data["confidence"] for e in events if e.type == "FINDING"}
        assert confidence == {"Dom-Based XSS": "CONFIRMED", "Client-Side Path Traversal to XSS": "MEDIUM"}


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
        tested = {name for _, name in module_test.scan.modules["domino"].tested_parameters}
        assert "search" in tested
        assert "q" not in tested, "DOMino loaded a JSON API's parameter as a page"
