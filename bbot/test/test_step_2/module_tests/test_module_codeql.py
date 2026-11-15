import collections
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from .base import ModuleTestBase
from bbot.modules.codeql.codeql import QUERIES_DIR
from bbot.test.worker import HTTPSERVER_URL

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
        # the inline script, the event handler and the external script, each reported once; the frame's script
        # runs in the frame's page, not this one
        assert len(findings) == 3, [f.data for f in findings]
        for finding in findings:
            assert finding.data["name"] == DOM_XSS
            assert finding.data["severity"] == "HIGH"
            assert finding.data["confidence"] == "MEDIUM"
        descriptions = sorted(f.data["description"] for f in findings)
        page_url = findings[0].data["url"]
        message = "Text from the page's URL is written into the page as HTML."
        inline = 'document.getElementById("greeting").innerHTML = decodeURIComponent(location.hash.substring(1));'
        handler = (
            '<a href="#" onclick="document.getElementById(\'search\').innerHTML = '
            'decodeURIComponent(location.hash)">search</a>'
        )
        assert descriptions == sorted(
            [
                f"{message} Source: [var query = decodeURIComponent(location.search.substring(1));] | "
                f'Sink: [document.getElementById("search").innerHTML = query;] (Line 2) in {HTTPSERVER_URL}/app.js',
                f"{message} Source: [{inline}] | Sink: [{inline}] in {page_url}",
                f"{message} Source: [{handler}] | Sink: [{handler}] in {page_url}",
            ]
        )

        # pages running the same code are analyzed once, so only the vulnerable and the clean code were
        module = module_test.scan.modules["codeql"]
        assert len(module.analyzed) == 2
        assert sorted(bool(findings) for findings in module.analyzed.values()) == [False, True]


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
            _, _, source, sink, message = module.to_finding(result, Path(root), {"app.js": f"{HTTPSERVER_URL}/app.js"})
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
