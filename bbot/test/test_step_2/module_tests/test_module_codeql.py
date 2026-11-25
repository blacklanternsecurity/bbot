import collections
import json
import re
import tempfile
import urllib.parse
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

from .base import ModuleTestBase
from bbot.modules.codeql.codeql import PARAMETERS_QUERY, QUERIES_DIR
from bbot.test.worker import HTTPSERVER_URL, LOCALHOST_URL

FIXTURES_DIR = Path(__file__).parent / "codeql_fixtures"
# each fixture, minified the way sites ship their code, by minify.sh
MINIFIED_DIR = FIXTURES_DIR / "minified"
# the class of finding a fixture line must produce, named after its query: `// $ dom-xss`, or `<!-- $ dom-xss -->`
MARKER = re.compile(r"(?://|<!--)\s*\$\s+([\w\s-]+?)\s*(?:-->)?\s*$")

DOM_XSS = "DOM-based cross-site scripting"

# an inline script and an event handler that write the decoded fragment into the page, an external script, and a
# frame whose own script does the same
PAGE = """<html><head><title>codeql test</title></head><body>
<p>{text}</p>
<div id="greeting"></div>
<div id="search"></div>
<a href="#" onclick="document.getElementById('search').innerHTML = decodeURIComponent(location.hash)">search</a>
<script>
document.getElementById("greeting").innerHTML = decodeURIComponent(location.hash.substring(1));
</script>
<script src="/app.js"></script>
<iframe src="/frame"></iframe>
</body></html>"""

# writes the decoded query string into the page
APP_JS = """var query = decodeURIComponent(location.search.substring(1));
document.getElementById("search").innerHTML = query;
"""

FRAME = """<html><body><div id="x"></div><script src="/frame.js"></script></body></html>"""
FRAME_JS = """document.getElementById("x").innerHTML = decodeURIComponent(location.hash.slice(1));"""

CLEAN_PAGE = """<html><head><title>codeql test</title></head><body>
<div id="greeting"></div>
<script>
document.getElementById("greeting").textContent = decodeURIComponent(location.hash.substring(1));
</script>
</body></html>"""


def fixture_markers():
    """{(fixture, line): set of classes} for every line marked in a fixture."""
    markers = {}
    for path in sorted(FIXTURES_DIR.rglob("*")):
        if path.suffix not in (".js", ".jsx", ".html") or MINIFIED_DIR in path.parents:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = MARKER.search(line)
            if match:
                markers[(str(path.relative_to(FIXTURES_DIR)), number)] = set(match.group(1).split())
    return markers


def query_classes():
    """{query name: class}, where each query's class is its file name."""
    return {re.search(r"@name\s+(.+)", q.read_text()).group(1).strip(): q.stem for q in QUERIES_DIR.glob("*.ql")}


class TestCodeQL(ModuleTestBase):
    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/other", f"{HTTPSERVER_URL}/clean"]
    modules_overrides = ["http", "codeql"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        pages = {
            "/": PAGE.format(text="Welcome"),
            # the same page
            "/same": PAGE.format(text="Welcome"),
            # the same code in a different page
            "/other": PAGE.format(text="Another page"),
            "/clean": CLEAN_PAGE,
            "/frame": FRAME,
        }
        for uri, page in pages.items():
            module_test.set_expect_requests({"uri": uri}, {"response_data": page, "content_type": "text/html"})
        for uri, script in (("/app.js", APP_JS), ("/frame.js", FRAME_JS)):
            module_test.set_expect_requests(
                {"uri": uri}, {"response_data": script, "content_type": "application/javascript"}
            )

    def check(self, module_test, events):
        pages = {f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/other"}
        findings = [e for e in events if e.type == "FINDING" and e.data["url"] in pages]
        # nothing in the clean page
        assert not [e for e in events if e.type == "FINDING" and e.data["url"] == f"{HTTPSERVER_URL}/clean"]
        # the external script's finding is all in a script the pages load, so it's reported once; the inline script's
        # and the event handler's are each page's own code, so each page has them; the frame's script runs in the
        # frame's page, not these
        assert len(findings) == 5, [f.data for f in findings]
        for finding in findings:
            assert finding.data["name"] == DOM_XSS
            assert finding.data["severity"] == "HIGH"
            assert finding.data["confidence"] == "MEDIUM"
        descriptions = sorted(f.data["description"] for f in findings)
        page_urls = sorted({f.data["url"] for f in findings})
        # "/same" is "/" again, so it isn't analyzed at all
        assert page_urls == [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/other"]
        message = "Text from the page's URL is written into the page as HTML."
        inline = 'document.getElementById("greeting").innerHTML = decodeURIComponent(location.hash.substring(1));'
        handler = (
            '<a href="#" onclick="document.getElementById(\'search\').innerHTML = '
            'decodeURIComponent(location.hash)">search</a>'
        )
        assert descriptions == sorted(
            [
                f"{message} Source: [var query = decodeURIComponent(location.search.substring(1));] | "
                f'Sink: [document.getElementById("search").innerHTML = query;] (Line 2) in {HTTPSERVER_URL}/app.js'
            ]
            + [
                f"{message} Source: [{code}] | Sink: [{code}] in {url}"
                for url in page_urls
                for code in (inline, handler)
            ]
        )

        # pages running the same code are analyzed once, so only the vulnerable and the clean code were
        module = module_test.scan.modules["codeql"]
        assert len(module.analyzed) == 2
        assert sorted(bool(findings) for findings, _ in module.analyzed.values()) == [False, True]


class TestCodeQLScriptCopies(ModuleTestBase):
    """A finding all in a script is reported once per host, however many pages load the script, and whatever URL each
    loads its copy from; another host has it too"""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/one", f"{HTTPSERVER_URL}/two", f"{LOCALHOST_URL}/one"]
    modules_overrides = ["http", "codeql"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        for name in ("one", "two"):
            page = f'<html><body><div id="search"></div><script src="/{name}/app.js"></script></body></html>'
            module_test.set_expect_requests({"uri": f"/{name}"}, {"response_data": page, "content_type": "text/html"})
            module_test.set_expect_requests(
                {"uri": f"/{name}/app.js"}, {"response_data": APP_JS, "content_type": "application/javascript"}
            )

    def check(self, module_test, events):
        hosts = sorted(str(e.host) for e in events if e.type == "FINDING" and str(e.module) == "codeql")
        assert hosts == ["127.0.0.1", "localhost"], hosts


# a page that replaces itself with what it fetches from a path the fragment picks; once loaded, its script is gone
SELF_WRITING_PAGE = """<html><head><title>codeql test</title></head><body><script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "/pages/" + location.hash.slice(1));
xhr.onload = function () {
  document.open();
  document.write(xhr.responseText);
  document.close();
};
xhr.send();
</script></body></html>"""


class TestCodeQLServedPage(ModuleTestBase):
    """Code a page had as the server sent it is analyzed, even when the loaded page no longer has it."""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "codeql"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"codeql": {"min_severity": "warning"}}}

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            {"uri": "/"}, {"response_data": SELF_WRITING_PAGE, "content_type": "text/html"}
        )
        module_test.set_expect_requests(
            {"uri": "/pages/"}, {"response_data": "<html><body>Welcome</body></html>", "content_type": "text/html"}
        )

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and e.data["url"] == f"{HTTPSERVER_URL}/"]
        assert [f.data["name"] for f in findings] == ["Client-side path traversal to XSS"], [f.data for f in findings]
        assert findings[0].data["severity"] == "MEDIUM"
        assert (
            findings[0]
            .data["description"]
            .startswith(
                "Text from the page's URL picks the path of a request whose response is written into the page as HTML."
            )
        )


PARAMETER_FIXTURES_DIR = Path(__file__).parent / "codeql_parameter_fixtures"


class TestCodeQLParameterQuery(ModuleTestBase):
    """The parameters query finds the URL parameters code reads by name and passes to a sink, and only those."""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"web": {"enable_browser": True}}

    async def check(self, module_test, events):
        module = module_test.module
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "db"
            assert await module.create_database(PARAMETER_FIXTURES_DIR, database)
            results = await module.run_queries(database, [str(PARAMETERS_QUERY)])
        assert {result["message"] for result in results} == {"next", "name", "returnUrl", "returnTo", "note"}


def long_constant_page():
    """
    A page's own settings, URL-encoded JSON with a % in every few characters, start a link that the page's URL ends:
    no javascript: URL. The page writes its decoded fragment into itself further on, which is DOM XSS.
    """
    settings = {f"item{i}": {"label": f"Item {i}", "tags": ["a", "b"]} for i in range(4000)}
    encoded = urllib.parse.quote(json.dumps(settings), safe="")
    return (
        f"var settings = {json.dumps(encoded)};\n"
        "document.getElementById('more').href = settings + location.hash.slice(1);\n"
        "document.body.innerHTML = decodeURIComponent(location.hash.slice(1));\n"
    )


class TestCodeQLLongConstants(ModuleTestBase):
    """Code with a long constant full of % signs, like URL-encoded JSON, is analyzed whole."""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"web": {"enable_browser": True}}

    async def check(self, module_test, events):
        module = module_test.module
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "src"
            source.mkdir()
            (source / "page.js").write_text(long_constant_page())
            database = Path(temp_dir) / "db"
            assert await module.create_database(source, database)
            results = await module.run_queries(database)
        assert [(result["name"], int(result["line"])) for result in results] == [(DOM_XSS, 3)], results


# a page sending the browser where its `next` parameter says
REDIRECTING_PAGE = """<html><head><title>codeql test</title></head><body><script>
location.href = new URLSearchParams(location.search).get("next");
</script></body></html>"""


class TestCodeQLParameters(ModuleTestBase):
    """A URL parameter a page's code passes to a sink is handed on to modules that test parameters, once per code."""

    pytestmark = pytest.mark.browser
    targets = [f"{HTTPSERVER_URL}/a", f"{HTTPSERVER_URL}/b"]
    # hunt tests parameters, which is what has codeql emit them
    modules_overrides = ["http", "codeql", "hunt"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"codeql": {"min_severity": "warning"}}}

    async def setup_after_prep(self, module_test):
        for uri in ("/a", "/b"):
            module_test.set_expect_requests(
                {"uri": uri}, {"response_data": REDIRECTING_PAGE, "content_type": "text/html"}
            )

    def check(self, module_test, events):
        parameters = [e.data for e in events if e.type == "WEB_PARAMETER" and str(e.module) == "codeql"]
        # both pages run the same code, so the parameter is handed on once
        assert [p["name"] for p in parameters] == ["next"], parameters
        assert parameters[0]["type"] == "GETPARAM"
        assert parameters[0]["url"] in (f"{HTTPSERVER_URL}/a", f"{HTTPSERVER_URL}/b")
        findings = [e.data["name"] for e in events if e.type == "FINDING" and str(e.module) == "codeql"]
        assert "DOM-based cross-site scripting" in findings


class TestCodeQLTimeout(ModuleTestBase):
    """A page CodeQL runs out of time on comes to nothing, rather than an error, and pages with its code don't rerun it"""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/other"]
    modules_overrides = ["http", "codeql"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        # two pages with the same code
        for uri, text in (("/", "Welcome"), ("/other", "Another page")):
            page = f"<html><body><p>{text}</p><script>document.title = location.hash;</script></body></html>"
            module_test.set_expect_requests({"uri": uri}, {"response_data": page, "content_type": "text/html"})
        module_test.codeql_runs = []

        async def run_process(command, **kwargs):
            module_test.codeql_runs.append(command[1:3])
            raise TimeoutError

        module_test.monkeypatch.setattr(module_test.module, "run_process", run_process)

    def check(self, module_test, events):
        module = module_test.module
        assert module.pages_seen == 2
        # the first page's database ran out of time; the second page has the same code, so it reused that result
        assert module_test.codeql_runs == [["database", "create"]]
        # a result is kept only if the analysis returned rather than raised
        assert list(module.analyzed.values()) == [([], [])]


OUT_OF_MEMORY = "CodeQL is out of memory. Try increasing the memory available to CodeQL using the --ram option."


class TestCodeQLOutOfMemory(ModuleTestBase):
    """
    A page CodeQL runs out of memory on comes to nothing, and so does one loading its scripts with at least as much
    code, without CodeQL trying it. Any other failure is tried again.
    """

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"web": {"enable_browser": True}}

    async def setup_after_prep(self, module_test):
        module_test.codeql_runs = []
        module_test.codeql_error = OUT_OF_MEMORY

        async def run_process(command, **kwargs):
            module_test.codeql_runs.append(command[1:3])
            return CompletedProcess(command, 2, "", module_test.codeql_error)

        module_test.monkeypatch.setattr(module_test.module, "run_process", run_process)

    async def check(self, module_test, events):
        module = module_test.module
        module_test.codeql_runs.clear()
        # analyzing a page works in the scan's temp dir, which the scan removes once it ends
        module.helpers.mkdir(module.scan.temp_dir)
        app = {"https://example.com/app.js": "var app = 1;\n" * 1000}
        other = {"https://example.com/other.js": "var app = 1;\n" * 1000}

        def page(size):
            return f"<html><body>{'a' * size}</body></html>"

        # out of memory
        assert await module.analyze_page(page(500), app) == ([], [])
        assert len(module_test.codeql_runs) == 1
        # its scripts, and more code: skipped
        assert await module.analyze_page(page(600), app) == ([], [])
        assert len(module_test.codeql_runs) == 1
        # its scripts, and less code, or other scripts: tried
        assert await module.analyze_page(page(400), app) == ([], [])
        assert await module.analyze_page(page(600), other) == ([], [])
        assert len(module_test.codeql_runs) == 3
        # a failure that isn't memory says nothing of the next page's
        module_test.codeql_error = "A fatal error occurred: the extractor stopped."
        empty = {"https://example.com/empty.js": ""}
        assert await module.analyze_page(page(500), empty) == ([], [])
        assert await module.analyze_page(page(600), empty) == ([], [])
        assert module_test.codeql_runs == [["database", "create"]] * 5


class TestCodeQLThirdPartyHosts(ModuleTestBase):
    """Analyzing every script leaves out those from listed third-party hosts, unless they're in scope."""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [HTTPSERVER_URL]
    config_overrides = {
        "web": {"enable_browser": True},
        "modules": {"codeql": {"mode": "all", "skip_hosts": ["googletagmanager.com", "127.0.0.1"]}},
    }

    def check(self, module_test, events):
        def script(url):
            return {"url": url, "resource_type": "script", "main_frame": True, "response": SimpleNamespace(text="1;")}

        in_scope = f"{HTTPSERVER_URL}/app.js"
        listed = "https://www.googletagmanager.com/gtm.js?id=GTM-TEST"
        unlisted = "https://cdn.example.org/lib.js"
        visit = SimpleNamespace(network=[script(in_scope), script(listed), script(unlisted)])
        assert sorted(module_test.module.page_scripts(visit)) == sorted([in_scope, unlisted])


class TestCodeQLMergedResult(ModuleTestBase):
    """A sink reached from several sources comes back as one result, its message a line for each, and reads once."""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [HTTPSERVER_URL]
    config_overrides = {"web": {"enable_browser": True}}

    def check(self, module_test, events):
        module = module_test.module
        line = 'Text from [["the page\'s URL"|"relative:///app.js:1:9:1:21"]] becomes the location the page goes to.'
        result = {
            "name": "Client-side open redirect",
            "description": "Input an attacker controls becomes the location the page navigates to.",
            "severity": "warning",
            "message": f"{line}\n{line.replace('1:9:1:21', '1:37:1:51')}",
            "file": "/app.js",
            "line": "2",
            "column": "17",
            "end_line": "2",
            "end_column": "22",
        }
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.js").write_text(
                "var a = location.hash.slice(1), b = location.search.slice(1);\nlocation.href = a || b;\n"
            )
            _, _, source, sink, message, _ = module.to_finding(
                result, Path(root), {"app.js": f"{HTTPSERVER_URL}/app.js"}
            )
        assert message == "Text from the page's URL becomes the location the page goes to."
        description = module.describe(f"{HTTPSERVER_URL}/", source, sink, message)
        assert description.startswith(f"{message} Source: [")
        assert description.count("becomes the location") == 1


class TestCodeQLQueries(ModuleTestBase):
    """Every query reports exactly the fixture lines marked with its class, and the same in each minified copy."""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"web": {"enable_browser": True}}

    async def check(self, module_test, events):
        module = module_test.module
        classes = query_classes()
        found = collections.defaultdict(collections.Counter)
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "db"
            assert await module.create_database(FIXTURES_DIR, database)
            for result in await module.run_queries(database):
                found[(result["file"].lstrip("/"), int(result["line"]))][classes[result["name"]]] += 1

        failures = []
        expected = fixture_markers()
        readable = {key: set(counts) for key, counts in found.items() if not key[0].startswith("minified/")}
        for key in sorted(set(expected) | set(readable)):
            for missed in sorted(expected.get(key, set()) - readable.get(key, set())):
                failures.append(f"missed {missed} at {key[0]}:{key[1]}")
            for extra in sorted(readable.get(key, set()) - expected.get(key, set())):
                failures.append(f"unexpected {extra} at {key[0]}:{key[1]}")

        # minified, each fixture gives the same findings, on its one line
        per_file = collections.defaultdict(collections.Counter)
        for (file, _), counts in found.items():
            per_file[file].update(counts)
        for copy in sorted(MINIFIED_DIR.rglob("*.js")):
            original = str(copy.relative_to(MINIFIED_DIR))
            if per_file[f"minified/{original}"] != per_file[original]:
                failures.append(
                    f"minified/{original} found {dict(per_file[f'minified/{original}'])}, "
                    f"its original {dict(per_file[original])}"
                )
        assert not failures, "\n".join(failures)


def test_codeql_fixtures():
    """Every query has fixtures it must find something in, minified as well, and every marker names a query."""
    classes = {query.stem for query in QUERIES_DIR.glob("*.ql")}
    markers = fixture_markers()
    marked = {c for found in markers.values() for c in found}
    assert marked <= classes, f"markers that name no query: {marked - classes}"
    assert classes <= marked, f"queries with no fixture to find something in: {classes - marked}"
    minified = {str(copy.relative_to(MINIFIED_DIR)) for copy in MINIFIED_DIR.rglob("*.js")}
    for query in classes:
        assert any(query in found and file in minified for (file, _), found in markers.items()), (
            f"{query} has no minified fixture to find something in"
        )
    # a copy of every JavaScript fixture, except AngularJS code injecting by parameter name, which minifying breaks
    originals = {
        str(path.relative_to(FIXTURES_DIR))
        for path in FIXTURES_DIR.rglob("*.js")
        if MINIFIED_DIR not in path.parents and "by parameter name" not in path.read_text().splitlines()[0]
    }
    assert minified == originals, "run codeql_fixtures/minify.sh"
