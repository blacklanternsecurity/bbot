import re
from urllib.parse import unquote

from werkzeug.wrappers import Response

from bbot.modules.wayback import wayback

from .base import ModuleTestBase


class TestWayback(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://asdf.blacklanternsecurity.com"]],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestWaybackParameters(ModuleTestBase):
    module_name = "wayback"
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    modules_overrides = ["wayback", "hunt"]
    config_overrides = {"modules": {"wayback": {"urls": True, "parameters": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                ["http://127.0.0.1:8888/page?foo=bar&baz=qux"],
            ],
        )
        # serve a response on the local httpserver so the httpx binary gets a 200
        module_test.set_expect_requests(expect_args={"uri": "/page"}, respond_args={"response_data": "alive"})

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "127.0.0.1" in e.url and "/page" in e.url for e in events), (
            "Failed to emit URL_UNVERIFIED"
        )
        assert any(
            e.type == "WEB_PARAMETER" and e.data["name"] == "foo" and e.data["original_value"] == "bar" for e in events
        ), "Failed to emit WEB_PARAMETER for foo"
        assert any(
            e.type == "WEB_PARAMETER" and e.data["name"] == "baz" and e.data["original_value"] == "qux" for e in events
        ), "Failed to emit WEB_PARAMETER for baz"
        # check that additional_params contains sibling params but excludes the current one
        for e in events:
            if e.type == "WEB_PARAMETER" and e.data["name"] == "foo":
                assert e.data["additional_params"] == {"baz": "qux"}, (
                    f"foo's additional_params wrong: {e.data['additional_params']}"
                )
            if e.type == "WEB_PARAMETER" and e.data["name"] == "baz":
                assert e.data["additional_params"] == {"foo": "bar"}, (
                    f"baz's additional_params wrong: {e.data['additional_params']}"
                )


class TestWaybackInterestingFiles(ModuleTestBase):
    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://blacklanternsecurity.com/backup/site.zip"]],
        )
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://blacklanternsecurity.com/backup/site.zip",
            headers={"Content-Type": "application/zip", "Content-Length": "1048576"},
        )

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "Interesting archived file found" in e.data["description"]
            and "site.zip" in e.data["description"]
            for e in events
        ), "Failed to emit FINDING for interesting archived file"
        for e in events:
            if e.type == "FINDING" and "site.zip" in e.data.get("description", ""):
                assert "web.archive.org" in e.data["url"]


class TestWaybackArchive(ModuleTestBase):
    module_name = "wayback"
    modules_overrides = ["wayback", "badsecrets", "excavate"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "archive": True}}}

    sample_viewstate = """<html>
<form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="rJdyYspajyiWEjvZ/SMXsU/1Q6Dp1XZ/19fZCABpGqWu+s7F1F/JT1s9mP9ED44fMkninhDc8eIq7IzSllZeJ9JVUME41i8ozheGunVSaESf4nBu" />
</div>
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
</form>
</html>"""

    async def setup_after_prep(self, module_test):
        # wayback returns a URL on an unreachable port — httpx binary can't verify it
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://127.0.0.1:1/deadpage"]],
        )
        # the archived page itself contains the vulnerable viewstate
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/deadpage",
            text=self.sample_viewstate,
            headers={"Content-Type": "text/html"},
        )

    def check(self, module_test, events):
        # the dead URL (port 1) should NOT be verified as live
        assert not any(e.type == "URL" and "deadpage" in e.url for e in events)
        # badsecrets should have found the vulnerability in the archived viewstate
        assert any(e.type == "FINDING" and "Known Secret Found." in e.data["description"] for e in events), (
            "Failed to detect badsecrets vulnerability from archived content"
        )
        # the vulnerability should reference the original URL, with "from-wayback" tag for provenance
        for e in events:
            if e.type == "FINDING" and "Known Secret Found." in e.data["description"]:
                assert "127.0.0.1" in e.data["url"], (
                    f"FINDING url should contain the original host, got: {e.data['url']}"
                )
                assert "web.archive.org" not in e.data["url"], (
                    f"FINDING url should NOT be an archive.org URL, got: {e.data['url']}"
                )
        # web.archive.org should NOT appear as a DNS_NAME event
        assert not any(e.type == "DNS_NAME" and e.data == "web.archive.org" for e in events), (
            "web.archive.org should not leak as a DNS_NAME event"
        )


class TestWaybackHttpHttpsDedup(ModuleTestBase):
    """When CDX returns both http:// and https:// for the same URL, only emit https://."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                ["http://blacklanternsecurity.com/page"],
                ["https://blacklanternsecurity.com/page"],
            ],
        )

    def check(self, module_test, events):
        url_unverified = [e for e in events if e.type == "URL_UNVERIFIED" and "/page" in e.url]
        # should have only one, the https version
        assert len(url_unverified) == 1, (
            f"Expected 1 URL_UNVERIFIED, got {len(url_unverified)}: {[e.url for e in url_unverified]}"
        )
        assert url_unverified[0].url.startswith("https://"), f"Expected https URL, got: {url_unverified[0].url}"


class TestWaybackHttpOnlyKept(ModuleTestBase):
    """When CDX returns only http:// (no https:// counterpart), emit the http:// URL."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                ["http://blacklanternsecurity.com/old-http-only"],
            ],
        )

    def check(self, module_test, events):
        url_unverified = [e for e in events if e.type == "URL_UNVERIFIED" and "/old-http-only" in e.url]
        assert len(url_unverified) == 1, f"Expected 1 URL_UNVERIFIED, got {len(url_unverified)}"
        assert url_unverified[0].url.startswith("http://"), (
            f"Expected http URL when no https exists, got: {url_unverified[0].url}"
        )


class TestWaybackCdnCgiBlacklist(ModuleTestBase):
    """cdn-cgi/ URLs (Cloudflare infrastructure) should be filtered out."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                ["https://blacklanternsecurity.com/cdn-cgi/challenge-platform/h/g/something"],
                ["https://blacklanternsecurity.com/real-page"],
            ],
        )

    def check(self, module_test, events):
        # cdn-cgi URL should be filtered
        assert not any(e.type == "URL_UNVERIFIED" and "cdn-cgi" in e.url for e in events), (
            "cdn-cgi URL should have been filtered"
        )
        # real page should still be emitted
        assert any(e.type == "URL_UNVERIFIED" and "real-page" in e.url for e in events), (
            "Non-cdn-cgi URL should have been emitted"
        )


class TestWaybackArchiveHostField(ModuleTestBase):
    """Archived HTTP_RESPONSE events should use original URL (not archive.org) to prevent cascade."""

    module_name = "wayback"
    modules_overrides = ["wayback", "excavate"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "archive": True}}}

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://127.0.0.1:1/archived-page"]],
        )
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/archived-page",
            text="<html><body>archived content</body></html>",
            headers={"Content-Type": "text/html"},
        )

    def check(self, module_test, events):
        http_responses = [e for e in events if e.type == "HTTP_RESPONSE" and "from-wayback" in e.tags]
        assert len(http_responses) >= 1, "Expected at least one archived HTTP_RESPONSE"
        for e in http_responses:
            # URL should be the ORIGINAL (not archive.org) so event.host returns the original host
            assert "web.archive.org" not in e.data["url"], (
                f"HTTP_RESPONSE url should NOT be an archive.org URL, got: {e.data['url']}"
            )
            assert "127.0.0.1" in e.data["url"], (
                f"HTTP_RESPONSE url should contain original host, got: {e.data['url']}"
            )
            # archive_url should contain the archive.org provenance URL
            assert "web.archive.org" in e.data.get("archive_url", ""), (
                f"HTTP_RESPONSE archive_url should be the archive.org URL, got: {e.data.get('archive_url')}"
            )
            # event.host should be the original host
            assert str(e.host) != "web.archive.org", f"event.host should be original host, got: {e.host}"
        # web.archive.org should NOT appear as a DNS_NAME event
        assert not any(e.type == "DNS_NAME" and e.data == "web.archive.org" for e in events), (
            "web.archive.org should not leak as a DNS_NAME event"
        )


class TestWaybackArchiveHuntFinding(ModuleTestBase):
    """When hunt processes a WEB_PARAMETER extracted from archived content,
    the resulting FINDING should have the original host and original URL — NOT web.archive.org."""

    module_name = "wayback"
    modules_overrides = ["wayback", "excavate", "hunt"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "archive": True}}}

    async def setup_after_prep(self, module_test):
        # CDX returns a dead URL (port 1 = unreachable) with a huntable form
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://127.0.0.1:1/search"]],
        )
        # the archived page contains a form with "redirect" — a known hunt parameter
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/search",
            text='<html><form method="GET" action="/search"><input name="redirect" value="test"></form></html>',
            headers={"Content-Type": "text/html"},
        )

    def check(self, module_test, events):
        # hunt should have found the "redirect" parameter as interesting
        hunt_findings = [
            e for e in events if e.type == "FINDING" and "redirect" in e.data.get("description", "").lower()
        ]
        assert len(hunt_findings) >= 1, (
            f"Expected at least one hunt FINDING for 'redirect' param, got: "
            f"{[(e.type, e.data.get('description', '')) for e in events if e.type == 'FINDING']}"
        )
        for finding in hunt_findings:
            # host must be the original, NOT web.archive.org
            assert finding.data.get("host") != "web.archive.org", (
                f"Hunt FINDING host should NOT be web.archive.org, got: {finding.data}"
            )
            assert finding.data.get("host") == "127.0.0.1", (
                f"Hunt FINDING host should be 127.0.0.1 (original), got: {finding.data.get('host')}"
            )
            # URL should NOT contain web.archive.org — it should be the original URL
            finding_url = finding.data.get("url", "")
            assert "web.archive.org" not in finding_url, (
                f"Hunt FINDING url should NOT contain web.archive.org, got: {finding_url}"
            )
            # from-wayback tag should propagate; archive_url is reachable via parent traversal
            assert "from-wayback" in finding.tags, (
                f"Hunt FINDING should have from-wayback tag, got tags: {finding.tags}"
            )
            assert finding.archive_url is not None, (
                "Hunt FINDING should be able to reach archive_url via parent traversal"
            )
            assert "web.archive.org" in finding.archive_url, (
                f"Hunt FINDING archive_url should be archive.org URL, got: {finding.archive_url}"
            )

        # WEB_PARAMETERs from archived content should have from-wayback tag and reachable archive_url
        archived_params = [
            e for e in events if e.type == "WEB_PARAMETER" and "redirect" in e.data.get("name", "").lower()
        ]
        for param in archived_params:
            assert "from-wayback" in param.tags, (
                f"WEB_PARAMETER from archived content should have from-wayback tag, got tags: {param.tags}"
            )
            assert param.archive_url is not None, (
                "WEB_PARAMETER from archived content should reach archive_url via parent traversal"
            )

        # web.archive.org should never appear as a DNS_NAME
        assert not any(e.type == "DNS_NAME" and e.data == "web.archive.org" for e in events), (
            "web.archive.org should not leak as a DNS_NAME event"
        )


class TestWaybackLightfuzzXSS(ModuleTestBase):
    """End-to-end: wayback discovers URL with param → httpx verifies → wayback emits WEB_PARAMETER → lightfuzz finds XSS."""

    module_name = "wayback"
    targets = ["blacklanternsecurity.com"]
    modules_overrides = ["wayback", "http", "lightfuzz", "excavate"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {
        "interactsh_disable": True,
        "modules": {
            "wayback": {"urls": True, "parameters": True},
            "lightfuzz": {"enabled_submodules": ["xss"]},
        },
    }

    def request_handler(self, request):
        qs = str(request.query_string.decode())
        if "search=" in qs:
            value = qs.split("search=")[1]
            if "&" in value:
                value = value.split("&")[0]
            return Response(
                f"<html><h1>Results for '{unquote(value)}'</h1></html>",
                status=200,
            )
        return Response("<html><p>default page</p></html>", status=200)

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["lightfuzz"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        # CDX returns a URL with a search parameter pointing at the local httpserver
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://127.0.0.1:8888/?search=test"]],
        )
        # httpserver handles httpx verification and lightfuzz probes
        expect_args = re.compile("/")
        module_test.set_expect_requests_handler(expect_args=expect_args, request_handler=self.request_handler)

    def check(self, module_test, events):
        # wayback should have emitted WEB_PARAMETER for "search"
        assert any(
            e.type == "WEB_PARAMETER" and e.data["name"] == "search" and "wayback" in e.data["description"].lower()
            for e in events
        ), "wayback failed to emit WEB_PARAMETER for search"
        # lightfuzz should have detected XSS
        assert any(
            e.type == "FINDING" and "XSS" in e.data["description"] and "search" in e.data["description"]
            for e in events
        ), (
            f"lightfuzz failed to detect XSS. FINDINGs: "
            f"{[(e.data.get('description', '')) for e in events if e.type == 'FINDING']}"
        )


class TestWaybackStripBodyArtifacts(ModuleTestBase):
    """Test that _strip_wayback_wrapper removes all archive.org artifacts from HTML body."""

    module_name = "wayback"
    modules_overrides = ["wayback"]

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"]],
        )

    def check(self, module_test, events):
        w = wayback.__new__(wayback)

        # test stripping of rewritten URLs
        body = '<a href="http://web.archive.org/web/20250101120000/http://example.com/page">link</a>'
        stripped = w._strip_wayback_wrapper(body)
        assert "web.archive.org" not in stripped
        assert "http://example.com/page" in stripped

        # test stripping of toolbar
        body = (
            "<!-- BEGIN WAYBACK TOOLBAR INSERT --><div>toolbar</div><!-- END WAYBACK TOOLBAR INSERT --><p>content</p>"
        )
        stripped = w._strip_wayback_wrapper(body)
        assert "toolbar" not in stripped
        assert "content" in stripped

        # test stripping of stale archive.org references (e.g. /web/submit form)
        body = '<form action="http://web.archive.org/web/submit"><input name="date"></form><p>real</p>'
        stripped = w._strip_wayback_wrapper(body)
        assert "web.archive.org" not in stripped
        assert "real" in stripped

        # test stripping of protocol-relative archive.org URLs
        body = '<script src="//archive.org/includes/athena.js"></script><p>content</p>'
        stripped = w._strip_wayback_wrapper(body)
        assert "archive.org" not in stripped
        assert "content" in stripped

        # test stripping of relative wayback URL rewrites (href)
        body = '<a href="/web/19971024185506/http://www.example.com/PDF%20files/data.pdf">link</a>'
        stripped = w._strip_wayback_wrapper(body)
        assert "/web/19971024185506/" not in stripped
        assert "http://www.example.com/PDF%20files/data.pdf" in stripped

        # test stripping of relative wayback URL rewrites with modifier suffix (im_ for images)
        body = '<img src="/web/19971024185506im_/http://www.example.com/images/logo.gif">'
        stripped = w._strip_wayback_wrapper(body)
        assert "/web/19971024185506im_/" not in stripped
        assert "http://www.example.com/images/logo.gif" in stripped

        # test stripping of relative wayback URL rewrites with js_ suffix
        body = '<script src="/web/20250529193232js_/https://www.example.com/script.js"></script>'
        stripped = w._strip_wayback_wrapper(body)
        assert "/web/20250529193232js_/" not in stripped
        assert "https://www.example.com/script.js" in stripped


class TestWaybackArchiveBloomDedup(ModuleTestBase):
    """When multiple archive URLs redirect to the same snapshot, bloom filter prevents duplicate HTTP_RESPONSEs."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "archive": True}}}

    async def setup_after_prep(self, module_test):
        # CDX returns two different dead URLs
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                ["http://127.0.0.1:1/page-a"],
                ["http://127.0.0.1:1/page-b"],
            ],
        )
        # both archive URLs redirect to the same archived snapshot
        redirect_target = "http://web.archive.org/web/20230101120000/http://127.0.0.1:1/same-page"
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/page-a",
            status_code=301,
            headers={"Location": redirect_target},
        )
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/page-b",
            status_code=301,
            headers={"Location": redirect_target},
        )
        # two responses for the redirect target (one consumed per redirect)
        for _ in range(2):
            module_test.blasthttp_mock.add_response(
                url=redirect_target,
                text="<html><body>archived content</body></html>",
                headers={"Content-Type": "text/html"},
            )

    def check(self, module_test, events):
        http_responses = [e for e in events if e.type == "HTTP_RESPONSE" and "from-wayback" in e.tags]
        assert len(http_responses) == 1, (
            f"Expected exactly 1 archived HTTP_RESPONSE (bloom dedup should prevent duplicate), got {len(http_responses)}"
        )


class TestWaybackArchiveRetry(ModuleTestBase):
    """Archive fetches that fail transiently (connection error) should be retried and succeed."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "archive": True}}}

    async def setup_after_prep(self, module_test):
        # speed up retries for testing
        module_test.scan.modules["wayback"]._archive_error_delay = 0.01
        module_test.scan.modules["wayback"]._archive_delay = 0
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://127.0.0.1:1/retry-page"]],
        )
        # first attempt: 503 (archive.org overloaded)
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/retry-page",
        )
        # retry attempt: 200
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/retry-page",
            text="<html><body>recovered content</body></html>",
            headers={"Content-Type": "text/html"},
        )

    def check(self, module_test, events):
        http_responses = [e for e in events if e.type == "HTTP_RESPONSE" and "from-wayback" in e.tags]
        assert len(http_responses) == 1, f"Expected 1 archived HTTP_RESPONSE from retry, got {len(http_responses)}"


class TestWaybackGarbageUrlFilter(ModuleTestBase):
    """Crawler-trap URLs with repeating path segments should be filtered out."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        # build a crawler-trap URL with repeating path segments (like the real-world example)
        repeating = "/themes/sites/example.com".lstrip("/")
        garbage_path = "/get-materials/" + "/".join([repeating] * 20)
        garbage_url = f"https://blacklanternsecurity.com{garbage_path}"
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                [garbage_url],
                ["https://blacklanternsecurity.com/real-page"],
            ],
        )

    def check(self, module_test, events):
        # garbage URL should be filtered
        assert not any(e.type == "URL_UNVERIFIED" and "get-materials" in e.url for e in events), (
            "Crawler-trap URL with repeating path segments should have been filtered"
        )
        # real page should still be emitted
        assert any(e.type == "URL_UNVERIFIED" and "real-page" in e.url for e in events), (
            "Non-garbage URL should have been emitted"
        )


class TestWaybackGarbageUrlLength(ModuleTestBase):
    """Excessively long URLs should be filtered out as garbage."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    async def setup_after_prep(self, module_test):
        # URL exceeding 2000 character limit
        long_url = "https://blacklanternsecurity.com/" + "a" * 2000
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[
                ["original"],
                [long_url],
                ["https://blacklanternsecurity.com/normal-page"],
            ],
        )

    def check(self, module_test, events):
        # long URL should be filtered
        assert not any(e.type == "URL_UNVERIFIED" and "aaaa" in e.url for e in events), (
            "Excessively long URL should have been filtered"
        )
        # normal page should still be emitted
        assert any(e.type == "URL_UNVERIFIED" and "normal-page" in e.url for e in events), (
            "Normal-length URL should have been emitted"
        )


class TestWaybackJunkUrlFilter(ModuleTestBase):
    """Bot-manager-style randomized URLs should be filtered by the built-in YARA junk rules."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    # Synthetic Akamai-style junk URLs: each path has 2+ random segments
    # mixing uppercase, lowercase, and digits/symbols.
    junk_urls = [
        "https://blacklanternsecurity.com/K8RIfwz/zxO29N1d2a4g/Q3rx/GjlB8/ZrcodWAG1Tpd/1KhpOA/0c5tzl-i2II/Es8jJD",
        "https://blacklanternsecurity.com/w9bx0E/UPcIqN7-eCer/Fgm0A2/z0IU7/GBxV7_4QEnK/knJ9z4IYXGGw/XWt6dak5Ao",
        "https://blacklanternsecurity.com/oq384ANPC0E/Hq2E2/yCFIf08-/Ln3Kln6oEWx7",
    ]
    # URLs that must survive the filter — includes the Akamai bot-manager endpoint
    # itself, a CamelCase REST API path, and a single mixed-case-with-symbol segment
    # (MYAPP_Auth alone shouldn't trip the threshold of 2).
    legit_urls = [
        "https://blacklanternsecurity.com/clientlibs/abc123def456",
        "https://blacklanternsecurity.com/_bm/get_params?type=get-akid",
        "https://blacklanternsecurity.com/api/v1/MyController/getStuff",
        "https://blacklanternsecurity.com/MYAPP_Auth/login.jsp?TYPE=33554432",
    ]

    async def setup_after_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], *([u] for u in self.junk_urls + self.legit_urls)],
        )

    def check(self, module_test, events):
        emitted = [e.url for e in events if e.type == "URL_UNVERIFIED"]
        for junk in self.junk_urls:
            assert not any(junk in u for u in emitted), f"Junk URL was not filtered: {junk}"
        for legit in self.legit_urls:
            # match on the path so http/https variant normalization doesn't cause spurious failures
            path = legit.split("blacklanternsecurity.com", 1)[1].split("?", 1)[0]
            assert any(path in u for u in emitted), f"Legit URL was filtered: {legit}"


class TestWaybackJunkUrlFilterUnicode(ModuleTestBase):
    """A multibyte URL preceding junk URLs must not desync the byte-offset
    mapping used to attribute YARA matches back to individual URLs."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"wayback": {"urls": True}}}

    # leading URL with multibyte characters: each 'ü' is 2 UTF-8 bytes, so a
    # char-count offset table would be misaligned for every URL after it,
    # causing junk matches to be attributed to the wrong URL.
    unicode_url = "https://blacklanternsecurity.com/" + ("ü" * 50)
    junk_urls = [
        "https://blacklanternsecurity.com/Aa1/Bb2/Cc3",
        "https://blacklanternsecurity.com/Dd4/Ee5/Ff6",
        "https://blacklanternsecurity.com/Gg7/Hh8/Ii9",
    ]
    # plain ASCII URL after the junk; must survive (proves good URLs aren't
    # dropped by a misattributed match, and that the pipeline emitted at all)
    legit_url = "https://blacklanternsecurity.com/about/contact"

    async def setup_after_prep(self, module_test):
        all_urls = [self.unicode_url, *self.junk_urls, self.legit_url]
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], *([u] for u in all_urls)],
        )

    def check(self, module_test, events):
        emitted = [e.url for e in events if e.type == "URL_UNVERIFIED"]
        assert any("/about/contact" in u for u in emitted), "Legit URL was filtered or pipeline emitted nothing"
        for junk in self.junk_urls:
            path = junk.split("blacklanternsecurity.com", 1)[1]
            assert not any(path in u for u in emitted), f"Junk URL leaked past filter: {junk}"


class TestWaybackArchive429Retry(ModuleTestBase):
    """Archive fetches that get 429 rate-limited should back off and retry successfully."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "archive": True}}}

    async def setup_after_prep(self, module_test):
        # speed up delays for testing
        module_test.scan.modules["wayback"]._archive_429_default_delay = 0.01
        module_test.scan.modules["wayback"]._archive_error_delay = 0.01
        module_test.scan.modules["wayback"]._archive_delay = 0
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://127.0.0.1:1/rate-limited-page"]],
        )
        # first attempt: 429 rate limited
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/rate-limited-page",
            status_code=429,
            headers={"Retry-After": "1"},
        )
        # retry after backoff: 200
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/web/http://127.0.0.1:1/rate-limited-page",
            text="<html><body>content after rate limit</body></html>",
            headers={"Content-Type": "text/html"},
        )

    def check(self, module_test, events):
        http_responses = [e for e in events if e.type == "HTTP_RESPONSE" and "from-wayback" in e.tags]
        assert len(http_responses) == 1, (
            f"Expected 1 archived HTTP_RESPONSE after 429 retry, got {len(http_responses)}"
        )


class TestWaybackWildcardSkip(ModuleTestBase):
    """When the target host is an HTTP wildcard, wayback should skip the CDX query entirely."""

    module_name = "wayback"
    modules_overrides = ["wayback"]
    targets = ["blacklanternsecurity.com"]

    async def setup_after_prep(self, module_test):
        async def mock_wildcard(scheme, host, port):
            return True

        module_test.scan.helpers.web.is_http_wildcard_host = mock_wildcard
        # CDX response that should NOT be queried
        module_test.blasthttp_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original&limit=100000&filter=!statuscode:404&filter=!statuscode:301&filter=!statuscode:302&filter=!mimetype:image/.*&filter=!mimetype:text/css&filter=!mimetype:warc/revisit",
            json=[["original"], ["http://asdf.blacklanternsecurity.com"]],
        )

    def check(self, module_test, events):
        assert not any(e.data == "asdf.blacklanternsecurity.com" for e in events), (
            "Wayback should have skipped CDX query for wildcard host"
        )
