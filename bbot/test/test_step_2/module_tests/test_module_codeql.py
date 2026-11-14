import tempfile
from pathlib import Path

import pytest
import yaml

from .base import ModuleTestBase
from bbot.modules.codeql.codeql import QUERIES_DIR
from bbot.test.worker import HTTPSERVER_URL

FIXTURES_DIR = Path(__file__).parent / "codeql_fixtures"
# each query, with the fixtures it must find something in, and the ones it must not
MANIFEST = yaml.safe_load((FIXTURES_DIR / "MANIFEST.yml").read_text())

DOM_XSS = "DOM-based Cross-Site Scripting (XSS)"
# GitHub's query for it
GITHUB_XSS = "Client-side cross-site scripting"

# an inline script and an event handler that write the URL fragment into the page, and an external script
PAGE = """<html><head><title>codeql test</title></head><body>
<p>{text}</p>
<div id="greeting"></div>
<div id="search"></div>
<a href="#" onclick="document.getElementById('search').innerHTML = location.hash">search</a>
<script>
document.getElementById("greeting").innerHTML = location.hash.substring(1);
</script>
<script src="/app.js"></script>
</body></html>"""

# writes the decoded query string into the page
APP_JS = """var query = decodeURIComponent(location.search.substring(1));
document.getElementById("search").innerHTML = query;
"""

CLEAN_PAGE = """<html><head><title>codeql test</title></head><body>
<div id="greeting"></div>
<script>
document.getElementById("greeting").textContent = location.hash.substring(1);
</script>
</body></html>"""


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
        }
        for uri, page in pages.items():
            module_test.set_expect_requests({"uri": uri}, {"response_data": page, "content_type": "text/html"})
        module_test.set_expect_requests(
            {"uri": "/app.js"}, {"response_data": APP_JS, "content_type": "application/javascript"}
        )

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        pages = {f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/other"}
        # nothing in the clean page, from our queries or GitHub's
        assert all(f.data["url"] in pages for f in findings), [f.data for f in findings]
        assert GITHUB_XSS in {f.data["name"] for f in findings}
        findings = [f for f in findings if f.data["name"] == DOM_XSS]
        # the inline script, the event handler and the external script, each reported once
        assert len(findings) == 3, [f.data for f in findings]
        for finding in findings:
            assert finding.data["severity"] == "HIGH"
            assert finding.data["confidence"] == "MEDIUM"
        descriptions = sorted(f.data["description"] for f in findings)
        page_url = findings[0].data["url"]
        assert descriptions == sorted(
            [
                f'Source: [var query = decodeURIComponent(location.search.substring(1));] | Sink: [document.getElementById("search").innerHTML = query;] (Line 2) in {HTTPSERVER_URL}/app.js',
                f'Source: [document.getElementById("greeting").innerHTML = location.hash.substring(1);] | Sink: [document.getElementById("greeting").innerHTML = location.hash.substring(1);] in {page_url}',
                f'Source: [<a href="#" onclick="document.getElementById(\'search\').innerHTML = location.hash">search</a>] | Sink: [<a href="#" onclick="document.getElementById(\'search\').innerHTML = location.hash">search</a>] in {page_url}',
            ]
        )

        # pages running the same code are analyzed once, so only the vulnerable and the clean code were
        module = module_test.scan.modules["codeql"]
        assert len(module.analyzed) == 2
        assert sorted(bool(findings) for findings in module.analyzed.values()) == [False, True]


class TestCodeQLQueries(ModuleTestBase):
    """Each query finds what it should in the fixtures, and nothing in the safe ones."""

    pytestmark = pytest.mark.browser
    module_name = "codeql"
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"web": {"enable_browser": True}}

    async def check(self, module_test, events):
        module = module_test.module
        failures = []
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "db"
            assert await module.create_database(FIXTURES_DIR, database)
            for query, expected in MANIFEST.items():
                results = await module.run_queries(database, [str(QUERIES_DIR / query)])
                found = {Path(result["file"]).name for result in results}
                for fixture in expected.get("should_find", []):
                    if fixture not in found:
                        failures.append(f"{query} found nothing in {fixture}")
                for fixture in expected.get("should_not_find", []):
                    if fixture in found:
                        failures.append(f"{query} found something in safe {fixture}")
        assert not failures, "\n".join(failures)


def test_codeql_manifest():
    queries = {path.name for path in QUERIES_DIR.glob("*.ql")}
    assert set(MANIFEST) == queries, "every query needs fixtures in MANIFEST.yml, and every entry a query"
    for query, expected in MANIFEST.items():
        assert expected.get("should_find"), f"{query} has no fixture it must find something in"
        for fixture in expected.get("should_find", []) + expected.get("should_not_find", []):
            assert (FIXTURES_DIR / fixture).is_file(), f"{query}'s fixture {fixture} doesn't exist"
