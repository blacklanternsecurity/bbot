import pytest

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
    targets = [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same", f"{HTTPSERVER_URL}/clean"]
    modules_overrides = ["http", "domino"]
    config_overrides = {"web": {"enable_browser": True}, "modules": {"domino": {"rules": ["xss-basic"]}}}

    async def setup_after_prep(self, module_test):
        for uri, page in (("/", VULNERABLE_PAGE), ("/same", VULNERABLE_PAGE), ("/clean", CLEAN_PAGE)):
            module_test.set_expect_requests({"uri": uri}, {"response_data": page, "content_type": "text/html"})

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 1
        finding = findings[0].data
        assert finding["name"] == "Dom-Based XSS"
        assert finding["severity"] == "HIGH"
        assert finding["confidence"] == "CONFIRMED"
        assert finding["url"].split("#")[0] in (f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/same")
        assert "alert() containing 'AAABBB' was executed" in finding["description"]

        # two URLs with the same body are one page to DOMino, so only one of them is scanned
        probed = {request.path for request, _ in module_test.httpserver.log if request.query_string}
        assert len(probed & {"/", "/same"}) == 1
        assert "/clean" in probed
