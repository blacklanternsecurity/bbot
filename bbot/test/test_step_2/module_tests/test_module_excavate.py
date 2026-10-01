from ...bbot_fixtures import *
from bbot.modules.base import BaseModule
from .base import ModuleTestBase, tempwordlist

from bbot.errors import ExcavateError
from bbot.modules.internal.excavate import ExcavateRule, split_yara_rules

from pathlib import Path
import time
import yara
from bbot.test.worker import HTTPSERVER_PORT, HTTPSERVER_URL, LOCALHOST_URL


class TestExcavate(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/", "test.notreal", f"{HTTPSERVER_URL}/subdir/links.html"]
    modules_overrides = ["excavate", "http"]
    config_overrides = {"web": {"spider_distance": 1, "spider_depth": 1}, "omit_event_types": []}

    async def setup_before_prep(self, module_test):
        response_data = """
        ftp://ftp.test.notreal
        \\nhttps://www1.test.notreal
        \\x3dhttps://www2.test.notreal
        %0ahttps://www3.test.notreal
        \\u000ahttps://www4.test.notreal:
        \nwww5.test.notreal
        \\x3dwww6.test.notreal
        %0awww7.test.notreal
        \\u000awww8.test.notreal
        <a href="/a_relative.txt">
        <link href="/link_relative.txt">
        <a href="mailto:bob@evilcorp.org?subject=help">Help</a>
        <li class="toctree-l3"><a class="reference internal" href="miscellaneous.html#x50-uart-driver">16x50 UART Driver</a></li>
        # these ones should get emitted as URL_UNVERIFIED events (processed by http module which has accept_js_url=True)
        <a href="/a_relative.js">
        <link href="/link_relative.js">
        """
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": response_data}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # verify relatives path a-tag parsing is working correctly

        expect_args = {"method": "GET", "uri": "/subdir/links.html"}
        respond_args = {"response_data": "<a href='../relative.html'/><a href='/2/depth2.html'/>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/relative.html"}
        respond_args = {"response_data": "<a href='/distance2.html'/>"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        module_test.httpserver.no_handler_status_code = 404

    async def setup_after_prep(self, module_test):
        # here we create a dummy module to consume all events including internal ones

        class DummyModule(BaseModule):
            watched_events = ["*"]
            _name = "dummy_module"
            accept_dupes = True
            accept_url_special = True
            events_seen = []

            async def handle_event(self, event):
                self.events_seen.append(event)

        module_test.scan.modules["dummy_module"] = DummyModule(module_test.scan)

    def check(self, module_test, events):
        event_data = [e.pretty_string for e in events]
        assert "https://www1.test.notreal/" in event_data
        assert "https://www2.test.notreal/" in event_data
        assert "https://www3.test.notreal/" in event_data
        assert "https://www4.test.notreal/" in event_data
        assert "www1.test.notreal" in event_data
        assert "www2.test.notreal" in event_data
        assert "www3.test.notreal" in event_data
        assert "www4.test.notreal" in event_data
        assert "www5.test.notreal" in event_data
        assert "www6.test.notreal" in event_data
        assert "www7.test.notreal" in event_data
        assert "www8.test.notreal" in event_data
        # .js files should be emitted as URL_UNVERIFIED events (they are processed by http module which has accept_js_url=True)
        # they are seen by internal modules but not by output modules
        assert f"{HTTPSERVER_URL}/a_relative.js" not in event_data
        assert f"{HTTPSERVER_URL}/link_relative.js" not in event_data
        assert f"{HTTPSERVER_URL}/a_relative.txt" in event_data
        assert f"{HTTPSERVER_URL}/link_relative.txt" in event_data
        dummy_module_event_data = [e.pretty_string for e in module_test.scan.modules["dummy_module"].events_seen]
        assert f"{HTTPSERVER_URL}/a_relative.js" in dummy_module_event_data
        assert f"{HTTPSERVER_URL}/link_relative.js" in dummy_module_event_data
        assert f"{HTTPSERVER_URL}/a_relative.txt" in dummy_module_event_data
        assert f"{HTTPSERVER_URL}/link_relative.txt" in dummy_module_event_data

        assert "nhttps://www1.test.notreal/" not in event_data
        assert "x3dhttps://www2.test.notreal/" not in event_data
        assert "a2https://www3.test.notreal/" not in event_data
        assert "uac20https://www4.test.notreal/" not in event_data

        assert any(
            e.type == "FINDING" and e.data.get("description", "") == "Non-HTTP URI: ftp://ftp.test.notreal"
            for e in events
        )
        assert any(
            e.type == "PROTOCOL"
            and e.data.get("protocol", "") == "FTP"
            and e.data.get("host", "") == "ftp.test.notreal"
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED"
            and e.url == f"{HTTPSERVER_URL}/relative.html"
            and "spider-max" not in e.tags
            and "endpoint" in e.tags
            and "extension-html" in e.tags
            and "in-scope" in e.tags
            and e.scope_distance == 0
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/2/depth2.html" and "spider-max" in e.tags
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/distance2.html" and "spider-max" in e.tags
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED" and "miscellaneous.html" in e.url and "x50-uart-driver" not in e.url
            for e in events
        )


class TestExcavate2(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/", "test.notreal", f"{HTTPSERVER_URL}/subdir/"]

    async def setup_before_prep(self, module_test):
        # root relative
        expect_args = {"method": "GET", "uri": "/rootrelative.html"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # page relative
        expect_args = {"method": "GET", "uri": "/subdir/pagerelative.html"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/subdir/"}
        respond_args = {
            "response_data": """
                <a href='/rootrelative.html'>root relative</a>
                <a href='pagerelative1.html'>page relative 1</a>
                <a href='./pagerelative2.html'>page relative 2</a>
                """
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        module_test.httpserver.no_handler_status_code = 404

    def check(self, module_test, events):
        root_relative_detection = False
        page_relative_detection_1 = False
        page_relative_detection_2 = False
        root_page_confusion_1 = False
        root_page_confusion_2 = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                # these cases represent the desired behavior for parsing relative links
                if e.url == f"{HTTPSERVER_URL}/rootrelative.html":
                    root_relative_detection = True
                if e.url == f"{HTTPSERVER_URL}/subdir/pagerelative1.html":
                    page_relative_detection_1 = True
                if e.url == f"{HTTPSERVER_URL}/subdir/pagerelative2.html":
                    page_relative_detection_2 = True

                # these cases indicates that excavate parsed the relative links incorrectly
                if e.url == f"{HTTPSERVER_URL}/pagerelative.html":
                    root_page_confusion_1 = True
                if e.url == f"{HTTPSERVER_URL}/subdir/rootrelative.html":
                    root_page_confusion_2 = True

        assert root_relative_detection, "Failed to properly excavate root-relative URL"
        assert page_relative_detection_1, "Failed to properly excavate page-relative URL"
        assert page_relative_detection_2, "Failed to properly excavate page-relative URL"
        assert not root_page_confusion_1, "Incorrectly detected page-relative URL"
        assert not root_page_confusion_2, "Incorrectly detected root-relative URL"


class TestExcavateInScopeJavascript(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http", "badsecrets"]

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            f"<script>window.location.href = '{HTTPSERVER_URL}/script.js';</script>"
        )
        module_test.httpserver.expect_request("/script.js").respond_with_data(
            "var = 'eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo';"
        )

    def check(self, module_test, events):
        found_js_url_event = bool([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/script.js"])
        found_excavate_jwt_finding = bool(
            [
                e
                for e in events
                if e.type == "FINDING" and "JWT" in e.data["description"] and str(e.module) == "excavate"
            ]
        )
        found_badsecrets_finding = bool([e for e in events if e.type == "FINDING" and str(e.module) == "badsecrets"])

        assert found_js_url_event, "Failed to find URL event for script.js"
        assert found_badsecrets_finding, "Failed to find BADSECRETs finding from script.js"
        assert found_excavate_jwt_finding, "Excavate should still emit JWT findings even when badsecrets is enabled"


class TestExcavateRedirect(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/relative/", f"{HTTPSERVER_URL}/nonhttpredirect/"]
    config_overrides = {"scope": {"report_distance": 1}, "omit_event_types": []}

    async def setup_before_prep(self, module_test):
        # absolute redirect
        module_test.httpserver.expect_request("/").respond_with_data(
            "", status=302, headers={"Location": "https://www.test.notreal/yep"}
        )
        module_test.httpserver.expect_request("/relative/").respond_with_data(
            "", status=302, headers={"Location": "./owa/"}
        )
        module_test.httpserver.expect_request("/relative/owa/").respond_with_data(
            "ftp://127.0.0.1:2121\nsmb://127.0.0.1\nssh://127.0.0.2"
        )
        module_test.httpserver.expect_request("/nonhttpredirect/").respond_with_data(
            "", status=302, headers={"Location": "awb://127.0.0.1:7777"}
        )
        module_test.httpserver.no_handler_status_code = 404

    def check(self, module_test, events):
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED" and e.url == "https://www.test.notreal/yep" and e.scope_distance == 1
            ]
        )
        assert 1 == len([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/relative/owa/"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "FINDING" and e.data["description"] == "Non-HTTP URI: awb://127.0.0.1:7777"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "PROTOCOL" and e.data["protocol"] == "AWB" and e.data.get("port", 0) == 7777
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "FINDING" and e.data["description"] == "Non-HTTP URI: ftp://127.0.0.1:2121"
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "PROTOCOL" and e.data["protocol"] == "FTP" and e.data.get("port", 0) == 2121
            ]
        )
        assert 1 == len(
            [e for e in events if e.type == "FINDING" and e.data["description"] == "Non-HTTP URI: smb://127.0.0.1"]
        )
        assert 1 == len(
            [e for e in events if e.type == "PROTOCOL" and e.data["protocol"] == "SMB" and "port" not in e.data]
        )
        assert 0 == len([e for e in events if e.type == "FINDING" and "ssh://127.0.0.1" in e.data["description"]])
        assert 0 == len([e for e in events if e.type == "PROTOCOL" and e.data["protocol"] == "SSH"])


class TestExcavateQuerystringRemoveTrue(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"url_querystring_remove": True, "url_querystring_collapse": True, "omit_event_types": []}
    lots_of_params = f"""
    <a href="{HTTPSERVER_URL}/endpoint?foo=1"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=2"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=3"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=4"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=5"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=6"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=7"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=8"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=9"/>
    <a href="{HTTPSERVER_URL}/endpoint?foo=10"/>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.lots_of_params)

    def check(self, module_test, events):
        assert len([e for e in events if e.type == "URL_UNVERIFIED"]) == 2
        assert len([e for e in events if e.type == "URL_UNVERIFIED" and e.url == f"{HTTPSERVER_URL}/endpoint"]) == 1


class TestExcavateQuerystringRemoveFalse(TestExcavateQuerystringRemoveTrue):
    config_overrides = {"url_querystring_remove": False, "url_querystring_collapse": True, "omit_event_types": []}

    def check(self, module_test, events):
        assert (
            len([e for e in events if e.type == "URL_UNVERIFIED" and e.url.startswith(f"{HTTPSERVER_URL}/endpoint?")])
            == 1
        )


class TestExcavateQuerystringCollapseFalse(TestExcavateQuerystringRemoveTrue):
    config_overrides = {"url_querystring_remove": False, "url_querystring_collapse": False, "omit_event_types": []}

    def check(self, module_test, events):
        assert (
            len([e for e in events if e.type == "URL_UNVERIFIED" and e.url.startswith(f"{HTTPSERVER_URL}/endpoint?")])
            == 10
        )


class TestExcavateMaxLinksPerPage(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"web": {"spider_links_per_page": 10, "spider_distance": 1}, "omit_event_types": []}

    lots_of_links = f"""
    <a href="{HTTPSERVER_URL}/1"/>
    <a href="{HTTPSERVER_URL}/2"/>
    <a href="{HTTPSERVER_URL}/3"/>
    <a href="{HTTPSERVER_URL}/4"/>
    <a href="{HTTPSERVER_URL}/5"/>
    <a href="{HTTPSERVER_URL}/6"/>
    <a href="{HTTPSERVER_URL}/7"/>
    <a href="{HTTPSERVER_URL}/8"/>
    <a href="{HTTPSERVER_URL}/9"/>
    <a href="{HTTPSERVER_URL}/10"/>
    <a href="{HTTPSERVER_URL}/11"/>
    <a href="{HTTPSERVER_URL}/12"/>
    <a href="{HTTPSERVER_URL}/13"/>
    <a href="{HTTPSERVER_URL}/14"/>
    <a href="{HTTPSERVER_URL}/15"/>
    <a href="{HTTPSERVER_URL}/16"/>
    <a href="{HTTPSERVER_URL}/17"/>
    <a href="{HTTPSERVER_URL}/18"/>
    <a href="{HTTPSERVER_URL}/19"/>
    <a href="{HTTPSERVER_URL}/20"/>
    <a href="{HTTPSERVER_URL}/21"/>
    <a href="{HTTPSERVER_URL}/22"/>
    <a href="{HTTPSERVER_URL}/23"/>
    <a href="{HTTPSERVER_URL}/24"/>
    <a href="{HTTPSERVER_URL}/25"/>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.lots_of_links)

    def check(self, module_test, events):
        url_unverified_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        # base URL + 25 links = 26
        assert len(url_unverified_events) == 26
        url_data = [
            e.pretty_string for e in url_unverified_events if "spider-max" not in e.tags and "spider-danger" in e.tags
        ]
        assert len(url_data) >= 10 and len(url_data) <= 12
        url_events = [e for e in events if e.type == "URL"]
        assert len(url_events) == 11


class TestExcavateCSP(TestExcavate):
    csp_test_header = "default-src 'self'; script-src asdf.test.notreal; object-src 'none';"

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"headers": {"Content-Security-Policy": self.csp_test_header}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.data == "asdf.test.notreal" for e in events)


class TestExcavateURL(TestExcavate):
    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "SomeSMooshedDATAhttps://asdffoo.test.notreal/some/path"
        )

    def check(self, module_test, events):
        assert any(e.data == "asdffoo.test.notreal" for e in events)
        assert any(e.url == "https://asdffoo.test.notreal/some/path" for e in events)


class TestExcavateURL_IP(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/", "127.0.0.2"]

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data("SomeSMooshedDATAhttps://127.0.0.2/some/path")

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.2" for e in events)
        assert any(e.url == "https://127.0.0.2/some/path" for e in events)


class TestExcavateSerializationNegative(TestExcavate):
    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html><p>llsdtVVFlJxhcGGYTo2PMGTRNFVKZxeKTVbhyosM3Sm/5apoY1/yUmN6HVcn+Xt798SPzgXQlZMttsqp1U1iJFmFO2aCGL/v3tmm/fs7itYsoNnJCelWvm9P4ic1nlKTBOpMjT5B5NmriZwTAzZ5ASjCKcmN8Vh=</p></html>"
        )

    def check(self, module_test, events):
        assert not any(e.type == "FINDING" for e in events), "Found Results without word boundary"


class TestExcavateSerializationPositive(TestExcavate):
    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            """<html>
<h1>.NET</h1>
<p>AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5TdHJpbmddXSwgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGFlMwEAAAAIQ29tcGFyZXIQSXRlbUNvdW50AQMAAAAJAwAAAAlTeXN0ZW0uU3RyaW5nW10FAAAACQIAAAAJBAAAAAkFAAAACRcAAAAJCgAAAAkLAAAACQwAAAAJDQAAAAkOAAAACQ8AAAAJEAAAAAkRAAAACRIAAAAJEwAAAA==</p>
<h1>Java</h1>
<p>rO0ABXQADUhlbGxvLCB3b3JsZCE=</p>
<h1>PHP (string)</h1>
<p>czoyNDoiSGVsbG8sIHdvcmxkISBNb3JlIHRleHQuIjs=</p>
<h1>PHP (array)</h1>
<p>YTo0OntpOjA7aToxO2k6MTtzOjE0OiJzZWNvbmQgZWxlbWVudCI7aToyO2k6MztpOjM7czoxODoiTW9yZSB0ZXh0IGluIGFycmF5Ijt9</p>
<h1>PHP (object)</h1>
<p>TzoxMjoiU2FtcGxlT2JqZWN0IjoyOntzOjg6InByb3BlcnR5IjtzOjEzOiJJbml0aWFsIHZhbHVlIjtzOjE2OiJhZGRpdGlvbmFsU3RyaW5nIjtzOjIxOiJFeHRyYSB0ZXh0IGluIG9iamVjdC4iO30=</p>
<h1>Compression</h1>
<p>H4sIAAAAAAAA/yu2MjS2UvJIzcnJ11Eozy/KSVFUsgYAZN5upRUAAAA=</p>
</html>
"""
        )

    def check(self, module_test, events):
        for serialize_type in ["Java", "DOTNET", "PHP_Array", "PHP_String", "PHP_Object", "Possible_Compressed"]:
            assert any(e.type == "FINDING" and serialize_type in e.data["description"] for e in events), (
                f"Did not find {serialize_type} Serialized Object"
            )


class TestExcavateNonHttpScheme(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/", "test.notreal"]

    non_http_scheme_html = """

    <html>
    <head>
    </head>
    <body>
    <p>hxxp://test.notreal</p>
    <p>ftp://test.notreal</p>
    <p>nonsense://test.notreal</p>
    <p>ws://test.notreal</p>
    <p>wss://test.notreal</p>
    </body>
    </html>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.non_http_scheme_html)

    def check(self, module_test, events):
        found_hxxp_url = False
        found_ftp_url = False
        found_nonsense_url = False
        found_ws_finding = False
        found_ws_url = False
        found_wss_url = False

        for e in events:
            if e.type == "FINDING":
                if e.data["description"] == "Non-HTTP URI: hxxp://test.notreal":
                    found_hxxp_url = True
                if e.data["description"] == "Non-HTTP URI: ftp://test.notreal":
                    found_ftp_url = True
                if "nonsense" in e.data["description"]:
                    found_nonsense_url = True
                if "ws://" in e.data.get("description", "") or "wss://" in e.data.get("description", ""):
                    found_ws_finding = True
            if e.type == "URL_UNVERIFIED":
                if e.data.get("url", "") == "http://test.notreal/":
                    found_ws_url = True
                if e.data.get("url", "") == "https://test.notreal/":
                    found_wss_url = True
        assert found_hxxp_url
        assert found_ftp_url
        assert not found_nonsense_url
        assert not found_ws_finding, "ws:// should not produce a FINDING"
        assert found_ws_url, "ws:// should be converted to http:// URL_UNVERIFIED"
        assert found_wss_url, "wss:// should be converted to https:// URL_UNVERIFIED"


class TestExcavateParameterExtraction(TestExcavate):
    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["excavate", "http", "hunt"]
    targets = [f"{HTTPSERVER_URL}/"]
    parameter_extraction_html = f"""
    <html>
    <head>
        <title>Get extract</title>
        <script>
            $.get("/test", {{jqueryget: "value1"}});
            $.post("/test", {{jquerypost: "value2"}});
        </script>
    </head>
    <body>
        <h1>Simple GET Form</h1>
        <p>Use the form below to submit a GET request:</p>
        <form action="/search" method="get">
            <label for="searchQuery">Search Query:</label>
            <input type="text" id="searchQuery" name="q1" value="flowers"><br><br>
            <input type="text" id="searchQueryspaces" name="q4" value="trees and forests"><br><br>
            <input type="submit" value="Search">
        </form>
        <h1>Simple POST Form</h1>
        <p>Use the form below to submit a POST request:</p>
        <form action="/search" method="post">
            <label for="searchQuery">Search Query:</label>
            <input type="text" id="searchQuery" name="q2" value="boats"><br><br>
            <input type="text" id="searchQuery2" name="q5" value="submarines"><br><br>
            <input type="submit" value="Search">
        </form>
        <h1>Simple Generic Form</h1>
        <p>Use the form below to submit a request:</p>
        <form action="/search">
            <label for="searchQuery">Search Query:</label>
            <input type="text" id="searchQuery" name="q3" value="candles"><br><br>
            <input type="submit" value="Search">
        </form>
        <p>Links</p>
        <a href="/validPath?id=123&age=456">href</a>
        <img src="{HTTPSERVER_URL}/validPath?size=m&fit=slim">img</a>
        <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <select id=blog-post-author-display name=blog-post-author-display form=blog-post-author-display-form>
        <option value=user.name selected>Name</option>
        <input required type="hidden" name="csrf" value="O0A5UIhlB2ezuMGC1oWr6XA6GhG4sUVj">
        </form>
    </body>
    </html>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.parameter_extraction_html)

    def check(self, module_test, events):
        found_jquery_get = False
        found_jquery_post = False
        found_form_get = False
        found_form_post = False
        found_form_generic = False
        found_jquery_get_original_value = False
        found_jquery_post_original_value = False
        found_form_get_original_value = False
        found_form_post_original_value = False
        found_form_generic_original_value = False
        found_htmltags_a = False
        found_htmltags_img = False
        found_select_noquotes = False
        avoid_truncated_values = True
        found_form_input_with_spaces = False
        found_form_get_additional_params = False
        found_form_post_additional_params = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if e.data["description"] == "HTTP Extracted Parameter [jqueryget] (GET jquery Submodule)":
                    found_jquery_get = True
                    if e.data["original_value"] == "value1":
                        found_jquery_get_original_value = True

                if e.data["description"] == "HTTP Extracted Parameter [jquerypost] (POST jquery Submodule)":
                    found_jquery_post = True
                    if e.data["original_value"] == "value2":
                        found_jquery_post_original_value = True

                if e.data["description"] == "HTTP Extracted Parameter [q1] (GET Form Submodule)":
                    found_form_get = True
                    if e.data["original_value"] == "flowers":
                        found_form_get_original_value = True
                        if "q4" in e.data["additional_params"].keys():
                            found_form_get_additional_params = True

                if e.data["description"] == "HTTP Extracted Parameter [q2] (POST Form Submodule)":
                    found_form_post = True
                    if e.data["original_value"] == "boats":
                        found_form_post_original_value = True
                        if "q5" in e.data["additional_params"].keys():
                            found_form_post_additional_params = True

                if e.data["description"] == "HTTP Extracted Parameter [q3] (Generic Form Submodule)":
                    found_form_generic = True
                    if e.data["original_value"] == "candles":
                        found_form_generic_original_value = True

                if e.data["description"] == "HTTP Extracted Parameter [age] (HTML Tags Submodule)":
                    if e.data["original_value"] == "456":
                        if "id" in e.data["additional_params"].keys():
                            found_htmltags_a = True

                if e.data["description"] == "HTTP Extracted Parameter [size] (HTML Tags Submodule)":
                    if e.data["original_value"] == "m":
                        if "fit" in e.data["additional_params"].keys():
                            found_htmltags_img = True

                if (
                    e.data["description"]
                    == "HTTP Extracted Parameter [blog-post-author-display] (POST Form Submodule)"
                ):
                    if e.data["original_value"] == "user.name":
                        if "csrf" in e.data["additional_params"].keys():
                            found_select_noquotes = True

                if e.data["description"] == "HTTP Extracted Parameter [q4] (GET Form Submodule)":
                    if e.data["original_value"] == "trees and forests":
                        found_form_input_with_spaces = True
                    if e.data["original_value"] == "trees":
                        avoid_truncated_values = False

        assert found_jquery_get, "Did not extract Jquery GET parameters"
        assert found_jquery_post, "Did not extract Jquery POST parameters"
        assert found_form_get, "Did not extract Form GET parameters"
        assert found_form_post, "Did not extract Form POST parameters"
        assert found_form_generic, "Did not extract Form (Generic) parameters"
        assert found_form_input_with_spaces, "Did not extract Form input with spaces"
        assert avoid_truncated_values, "Emitted a parameter with spaces without the entire value"
        assert found_jquery_get_original_value, "Did not extract Jquery GET parameter original_value"
        assert found_jquery_post_original_value, "Did not extract Jquery POST parameter original_value"
        assert found_form_get_original_value, "Did not extract Form GET parameter original_value"
        assert found_form_post_original_value, "Did not extract Form POST parameter original_value"
        assert found_form_generic_original_value, "Did not extract Form (Generic) parameter original_value"
        assert found_htmltags_a, "Did not extract parameter(s) from a-tag"
        assert found_htmltags_img, "Did not extract parameter(s) from img-tag"
        assert found_select_noquotes, "Did not extract parameter(s) from select-tag"
        assert found_form_get_additional_params, "Did not extract additional parameters from GET form"
        assert found_form_post_additional_params, "Did not extract additional parameters from POST form"


class TestExcavateSelectTagSelection(ModuleTestBase):
    """Verify <select> option-value selection logic.

    1. selected_nonfirst -- a non-first option carries `selected` -> we pick it (not the first option)
    2. first_empty -- first option is empty, no selected -> we keep the empty first value
       (filter-style forms often use a blank default that matches all results; substituting
       a specific choice could narrow output to nothing)
    3. selected_with_empty_first -- first option empty, non-first option carries `selected` -> we pick selected
    4. selected_empty -- the option with `selected` has an empty value -> we keep the empty
       selected value (the form's author chose blank as the default; preserve that intent)
    """

    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "hunt"]
    select_extract_html = """
    <html>
    <body>
        <form action="/sel1" method="post">
            <select name="selected_nonfirst">
                <option value="user">User</option>
                <option value="admin" selected>Admin</option>
                <option value="guest">Guest</option>
            </select>
            <input type="submit" value="go">
        </form>
        <form action="/sel2" method="post">
            <select name="first_empty">
                <option value="">-- choose --</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
            </select>
            <input type="submit" value="go">
        </form>
        <form action="/sel3" method="post">
            <select name="selected_with_empty_first">
                <option value="">-- choose --</option>
                <option value="us-east" selected>US East</option>
                <option value="eu-west">EU West</option>
            </select>
            <input type="submit" value="go">
        </form>
        <form action="/sel4" method="post">
            <select name="selected_empty">
                <option value="" selected>None</option>
                <option value="">blank too</option>
                <option value="fallback">Fallback</option>
            </select>
            <input type="submit" value="go">
        </form>
    </body>
    </html>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.select_extract_html, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        picked = {}
        for e in events:
            if e.type != "WEB_PARAMETER":
                continue
            name = e.data.get("name")
            if name in (
                "selected_nonfirst",
                "first_empty",
                "selected_with_empty_first",
                "selected_empty",
            ):
                picked[name] = e.data.get("original_value")

        assert "selected_nonfirst" in picked, "Did not extract WEB_PARAMETER for selected_nonfirst"
        assert picked["selected_nonfirst"] == "admin", (
            f"selected_nonfirst: expected the option with `selected` to win, got {picked['selected_nonfirst']!r}"
        )

        assert "first_empty" in picked, "Did not extract WEB_PARAMETER for first_empty"
        assert picked["first_empty"] == "", (
            f"first_empty: expected the first option's empty value to be preserved when no option is selected, got {picked['first_empty']!r}"
        )

        assert "selected_with_empty_first" in picked, "Did not extract WEB_PARAMETER for selected_with_empty_first"
        assert picked["selected_with_empty_first"] == "us-east", (
            f"selected_with_empty_first: expected `selected` to win over the empty first option, got {picked['selected_with_empty_first']!r}"
        )

        assert "selected_empty" in picked, "Did not extract WEB_PARAMETER for selected_empty"
        assert picked["selected_empty"] == "", (
            f"selected_empty: expected the selected option's empty value to be preserved, got {picked['selected_empty']!r}"
        )


class TestExcavateParameterExtraction_postform_noaction(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]

    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["http", "excavate", "hunt"]
    postform_extract_html = """
<body>
    <h1>Post for without action</h1>
    <form method="post">
        <label for="state">Encrypted State:</label>
        <input type="text" name="state" id="state" value="voCcc4U5jnFWOYYF4Oueau3l8gDsTecHMxniZJSKvh4bSA0WCgEYAxFkdWJzbGJ+" size="100">
        <br><br>
        <input type="submit" value="Decrypt">
    </form>
</body>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.postform_extract_html, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_formnoaction_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [state] (POST Form (no action) Submodule)" in e.data["description"]:
                    excavate_formnoaction_extraction = True
        assert excavate_formnoaction_extraction, "Excavate failed to extract web parameter"


class TestExcavateParameterExtraction_postform_htmlencodedaction(TestExcavateParameterExtraction_postform_noaction):
    postform_extract_html = """
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    <body onload="document.forms[0].submit()">
        <noscript>
            <p>
                <strong>Note:</strong> Since your browser does not support JavaScript,
                you must press the Continue button once to proceed.
            </p>
        </noscript>
        <form action="https&#x3a;&#x2f;&#x2f;127.0.0.1&#x3a;8080&#x2f;sso-web&#x2f;singleSignOn.action" method="post">
            <div>
                <input type="hidden" name="value" value="PD94"/>                              
            </div>
            <noscript>
                <div>
                    <input type="submit" value="Continue"/>
                </div>
            </noscript>
        </form>
    </body>
</html>
    """

    def check(self, module_test, events):
        excavate_handle_htmlencoded_action = True
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "HTTP Extracted Parameter [value] (POST Form Submodule)" in e.data["description"]
                    and e.data["url"] == "https://127.0.0.1:8080/sso-web/singleSignOn.action"
                ):
                    excavate_handle_htmlencoded_action = True
        assert excavate_handle_htmlencoded_action, "Excavate failed to extract web parameter"


class TestExcavateParameterExtraction_additionalparams(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]

    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["http", "excavate", "hunt"]
    postformnoaction_extract_multiparams_html = """
<body>
    <h1>Post for without action</h1>
 <form id="templateForm" method="POST">
                        <input required type="hidden" name="csrf" value="MwARfZ19btvV2OjHIvTU5vVSGp9OyrcI">
                        <label>Template:</label>
                        <textarea required rows="12" cols="300" name="template">somenonsense</textarea>
                        <button class="button" type="submit" name="template-action" value="save">
                            Save
                        </button>
                    </form>
</body>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {
            "response_data": self.postformnoaction_extract_multiparams_html,
            "headers": {"Content-Type": "text/html"},
        }
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_additionalparam_extraction_param1 = False
        excavate_additionalparam_extraction_param2 = False
        excavate_additionalparam_extraction_param3 = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    e.data["name"] == "template-action"
                    and "csrf" in e.data["additional_params"].keys()
                    and "template" in e.data["additional_params"].keys()
                ):
                    excavate_additionalparam_extraction_param1 = True
                if (
                    e.data["name"] == "template"
                    and "csrf" in e.data["additional_params"].keys()
                    and "template-action" in e.data["additional_params"].keys()
                ):
                    excavate_additionalparam_extraction_param2 = True
                if (
                    e.data["name"] == "csrf"
                    and "template" in e.data["additional_params"].keys()
                    and "template-action" in e.data["additional_params"].keys()
                ):
                    excavate_additionalparam_extraction_param3 = True
        assert excavate_additionalparam_extraction_param1, (
            "Excavate failed to extract web parameter with correct additional data (param 1)"
        )
        assert excavate_additionalparam_extraction_param2, (
            "Excavate failed to extract web parameter with correct additional data (param 2)"
        )
        assert excavate_additionalparam_extraction_param3, (
            "Excavate failed to extract web parameter with correct additional data (param 3)"
        )


class TestExcavateParameterExtraction_getparam(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]

    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["http", "excavate", "hunt"]
    getparam_extract_html = """
<html><a href="/?hack=1">ping</a></html>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.getparam_extract_html, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_getparam_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [hack] (HTML Tags Submodule)" in e.data["description"]:
                    excavate_getparam_extraction = True
        assert excavate_getparam_extraction, "Excavate failed to extract web parameter"


class TestExcavateParameterExtraction_relativeurl(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]

    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["http", "excavate", "hunt"]
    config_overrides = {"web": {"spider_distance": 2, "spider_depth": 3}}

    # Secondary page that has a relative link to a traversal URL
    secondary_page_html = """
    <html>
        <a href="../root.html">Go to root</a>
    </html>
    """

    # Primary page that leads to the secondary page
    primary_page_html = """
    <html>
        <a href="/secondary">Go to secondary page</a>
    </html>
    """

    # Root page content
    root_page_html = "<html>Root page</html>"

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.primary_page_html)
        module_test.httpserver.expect_request("/secondary").respond_with_data(self.secondary_page_html)
        module_test.httpserver.expect_request("/root.html").respond_with_data(self.root_page_html)

    def check(self, module_test, events):
        # Validate that the traversal was successful and WEB_PARAMETER was extracted
        traversed_to_root = False
        parameter_extraction_found = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter" in e.data["description"]:
                    parameter_extraction_found = True

            if e.type == "URL":
                if "root.html" in e.parsed_url.path:
                    traversed_to_root = True

        assert traversed_to_root, "Failed to follow the relative traversal to /root.html"
        assert parameter_extraction_found, "Excavate failed to extract parameter after traversal"


class TestExcavateParameterExtraction_getparam_novalue(TestExcavateParameterExtraction_getparam):
    getparam_extract_html = """
                   <section class=search>
                        <form action="/catalog" method=GET>
                            <input type=text id="searchBar" placeholder="Search products" name="searchTerm">
                            <input type=text id="searchBar2" placeholder="Search products2" name="searchTerm2">
                            <script>
                                var searchText = '';
                                document.getElementById('searchBar').value = searchText;
                            </script>
                            <button type=submit class=button>Search</button>
                        </form>
                    </section>
    """

    def check(self, module_test, events):
        excavate_getparam_extraction = False
        found_no_value_additional_params = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [searchTerm] (GET Form Submodule)" in e.data["description"]:
                    excavate_getparam_extraction = True
                    if "searchTerm2" in e.data["additional_params"].keys():
                        found_no_value_additional_params = True
        assert excavate_getparam_extraction, "Excavate failed to extract web parameter"
        assert found_no_value_additional_params, (
            "Excavate failed to extract additional parameters for input tag with no value"
        )


class TestExcavateParameterExtraction_json(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "paramminer_getparams"]
    config_overrides = {
        "modules": {
            "excavate": {"speculate_params": True},
            "paramminer_getparams": {"wordlist": tempwordlist([]), "recycle_words": True},
        }
    }
    getparam_extract_json = """
    {
  "obscureParameter": 1,
  "common": 1
}
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.getparam_extract_json, "headers": {"Content-Type": "application/json"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_json_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "HTTP Extracted Parameter (speculative from json content) [obscureParameter]"
                    in e.data["description"]
                ):
                    excavate_json_extraction = True
        assert excavate_json_extraction, "Excavate failed to extract json parameter"


class TestExcavateParameterExtraction_xml(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "paramminer_getparams"]
    config_overrides = {
        "modules": {
            "excavate": {"speculate_params": True},
            "paramminer_getparams": {"wordlist": tempwordlist([]), "recycle_words": True},
        }
    }
    getparam_extract_xml = """
    <data>
     <obscureParameter>1</obscureParameter>
         <common>1</common>
     </data>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.getparam_extract_xml, "headers": {"Content-Type": "application/xml"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_xml_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "HTTP Extracted Parameter (speculative from xml content) [obscureParameter]"
                    in e.data["description"]
                ):
                    excavate_xml_extraction = True
        assert excavate_xml_extraction, "Excavate failed to extract xml parameter"


class TestExcavateParameterExtraction_xml_invalid(TestExcavateParameterExtraction_xml):
    getparam_extract_xml = """
    <data>
     <obscureParameter>1</obscureParameter>
         <newlines>invalid\nwith\nnewlines</newlines>
     </data>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.getparam_extract_xml, "headers": {"Content-Type": "application/xml"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_xml_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "HTTP Extracted Parameter (speculative from xml content) [newlines]" in e.data["description"]
                    and "\n" not in e.data["original_value"]
                ):
                    excavate_xml_extraction = True
        assert excavate_xml_extraction, "Excavate failed to extract xml parameter"


class TestExcavateParameterExtraction_inputtagnovalue(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]

    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["http", "excavate", "hunt"]
    getparam_extract_html = """
<form action=/ method=GET><input type=text name="novalue"><button type=submit class=button>Submit</button></form>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.getparam_extract_html, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_getparam_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [novalue] (GET Form Submodule)" in e.data["description"]:
                    excavate_getparam_extraction = True
        assert excavate_getparam_extraction, "Excavate failed to extract web parameter"


class TestExcavateParameterExtraction_jqueryjsonajax(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "hunt"]
    jsonajax_extract_html = """
    <html>
    <script>
    function doLogin(e) {
      e.preventDefault();
      var username = $("#usernamefield").val();
      var password = $("#passwordfield").val();
      $.ajax({
        url: '/api/auth',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ username: username, password: password }),
        success: function (r) {
          window.location.replace("/demo");
        },
        error: function (r) {
          if (r.status == 401) {
            notify("Access denied");
          } else {
            notify(r.responseText);
          }
        }
      });
    }
    </html>
<form action=/ method=GET><input type=text name="novalue"><button type=submit class=button>Submit</button></form>
    """

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.jsonajax_extract_html, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_ajaxpost_extraction = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "HTTP Extracted Parameter [username] (JQuery Extractor Submodule)" == e.data["description"]
                    and e.data["original_value"] is None
                ):
                    excavate_ajaxpost_extraction = True
        assert excavate_ajaxpost_extraction, "Excavate failed to extract web parameter"


class excavateTestRule(ExcavateRule):
    yara_rules = {
        "SearchForText": 'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
        "SearchForText2": 'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text2 = "DDDDEEEEFFFF" condition: $text2 }',
    }


class TestExcavateYara(TestExcavate):
    targets = [f"{HTTPSERVER_URL}/"]
    yara_test_html = """
    <html>
<head>
</head>
<body>
<p>AAAABBBBCCCC</p>
<p>filler</p>
<p>DDDDEEEEFFFF</p>
</body>
</html>
"""

    async def setup_before_prep(self, module_test):
        self.modules_overrides = ["excavate", "http"]
        module_test.httpserver.expect_request("/").respond_with_data(self.yara_test_html)

    async def setup_after_prep(self, module_test):
        excavate_module = module_test.scan.modules["excavate"]
        excavateruleinstance = excavateTestRule(excavate_module)
        excavate_module.add_yara_rule(
            "SearchForText",
            'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
            excavateruleinstance,
        )
        excavate_module.add_yara_rule(
            "SearchForText2",
            'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text2 = "DDDDEEEEFFFF" condition: $text2 }',
            excavateruleinstance,
        )
        excavate_module.yara_rules = yara.compile(source="\n".join(excavate_module.yara_rules_dict.values()))

    def check(self, module_test, events):
        found_yara_string_1 = False
        found_yara_string_2 = False
        for e in events:
            if e.type == "FINDING":
                if e.data["description"] == "HTTP response (body) Contains the text AAAABBBBCCCC":
                    found_yara_string_1 = True
                if e.data["description"] == "HTTP response (body) Contains the text DDDDEEEEFFFF":
                    found_yara_string_2 = True

        assert found_yara_string_1, "Did not extract Match YARA rule (1)"
        assert found_yara_string_2, "Did not extract Match YARA rule (2)"


class TestExcavateYaraCustom(ModuleTestBase):
    """Custom YARA rules loaded via config must emit FINDINGs through CustomExtractor,
    propagating description, severity, confidence, tags, and emit_match from rule meta."""

    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http"]

    rule_file = [
        'rule CustomYaraFull { meta: description = "custom rule with full meta" severity = "HIGH" confidence = "CONFIRMED" tags = "custom-yara-tag" emit_match = true strings: $marker = "CUSTOMYARAFULLMARKER" condition: $marker }',
        'rule CustomYaraBare { meta: description = "custom rule without severity meta" strings: $marker = "CUSTOMYARABAREMARKER" condition: $marker }',
    ]
    f = tempwordlist(rule_file)
    config_overrides = {"modules": {"excavate": {"custom_yara_rules": f}}}

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html><body><p>CUSTOMYARAFULLMARKER</p><p>CUSTOMYARABAREMARKER</p></body></html>"
        )

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        descriptions = [e.data["description"] for e in findings]

        full = [e for e in findings if "[CustomYaraFull]" in e.data["description"]]
        assert full, f"Custom YARA rule CustomYaraFull produced no FINDING, got: {descriptions}"
        full = full[0]
        assert full.data["description"] == (
            "Custom Yara Rule [CustomYaraFull] with description: [custom rule with full meta] "
            "Matched via identifier [marker] and extracted [CUSTOMYARAFULLMARKER]"
        ), f"Wrong description: {full.data['description']}"
        assert full.data["severity"] == "HIGH", f"severity meta did not propagate: {full.data.get('severity')}"
        assert full.data["confidence"] == "CONFIRMED", (
            f"confidence meta did not propagate: {full.data.get('confidence')}"
        )
        assert "confidence-confirmed" in full.tags, f"Missing confidence tag: {full.tags}"
        assert "custom-yara-tag" in full.tags, f"tags meta did not propagate: {full.tags}"

        bare = [e for e in findings if "[CustomYaraBare]" in e.data["description"]]
        assert bare, f"Custom YARA rule CustomYaraBare produced no FINDING, got: {descriptions}"
        bare = bare[0]
        assert bare.data["severity"] == "INFO", f"Wrong default severity: {bare.data.get('severity')}"
        assert bare.data["confidence"] == "UNKNOWN", f"Wrong default confidence: {bare.data.get('confidence')}"


def test_split_yara_rules():
    """Rule splitting is brace-depth aware: a brace inside a string, hex string, comment, or
    regex must not end a rule early, and a rule name must survive arbitrary whitespace."""

    def names(source):
        return [name for name, _ in split_yara_rules(source)[1]]

    # a literal brace inside an earlier rule must not swallow the rules that follow
    three_rules = (
        'rule First { meta: description = "brace { inside" strings: $a = "a" condition: $a }\n'
        'rule Second { strings: $b = "b" condition: $b }\n'
        'rule Third { strings: $c = "c" condition: $c }'
    )
    assert names(three_rules) == ["First", "Second", "Third"]

    # whitespace around the rule name and opening brace is arbitrary
    assert names('rule Spaced  { strings: $a = "a" condition: $a }') == ["Spaced"]
    assert names('rule  Spaced2 { strings: $a = "a" condition: $a }') == ["Spaced2"]
    assert names('rule Newline\n{\n strings:\n  $a = "a"\n condition:\n  $a\n}') == ["Newline"]
    assert names('rule Tagged : tag1 tag2 { strings: $a = "a" condition: $a }') == ["Tagged"]

    # braces inside hex strings, comments, and regexes are not rule boundaries
    assert names("rule Hex { strings: $h = { 4D 5A [0-4] ( 62 B3 | 87 ) ?? } condition: $h }") == ["Hex"]
    assert names('rule Line { // }\n strings: $a = "a" condition: $a }') == ["Line"]
    assert names('rule Block { /* } { */ strings: $a = "a" condition: $a }') == ["Block"]
    assert names("rule Re { strings: $r = /ab{2,3}c/ nocase condition: $r }") == ["Re"]
    assert names("rule Re2 { strings: $r = /[a-z/]{1,3}/ condition: $r }") == ["Re2"]
    assert names(r'rule Esc { strings: $a = "quote \" then { " condition: $a }') == ["Esc"]

    # rule modifiers are preserved in the extracted rule text
    modifier_rules = split_yara_rules('global private rule Mod { strings: $a = "a" condition: $a }')[1]
    assert modifier_rules[0][0] == "Mod"
    assert modifier_rules[0][1].startswith("global private rule Mod")

    # imports are collected separately so each rule still compiles on its own
    imports, rules = split_yara_rules('import "pe"\nimport "math"\nrule UsesPe { condition: pe.entry_point > 0 }')
    assert imports == ['import "pe"', 'import "math"']
    assert [name for name, _ in rules] == ["UsesPe"]

    # unparseable input raises instead of silently dropping rules
    for bad in (
        'rule Unterminated { strings: $a = "a"',
        'rule BadString { strings: $a = "unterminated',
        "rule BadRegex { strings: $a = /unterminated",
        "rule BadComment { /* unterminated",
        "not_a_rule here",
        'include "other.yar"',
        "rule { condition: true }",
    ):
        with pytest.raises(ExcavateError):
            split_yara_rules(bad)


class TestExcavateYaraCustomEdgeCases(ModuleTestBase):
    """Custom rules whose text contains braces in strings, hex strings, comments, or regexes
    must all load and fire, rather than being dropped by the rule splitter."""

    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http"]

    rule_file = [
        'rule CustomBraceInString { meta: description = "brace { in a string" strings: $marker = "CUSTOMBRACEMARKER" condition: $marker }',
        'rule CustomTwoSpaces  { meta: description = "two spaces before brace" strings: $marker = "CUSTOMSPACEMARKER" condition: $marker }',
        'rule CustomHexString { meta: description = "hex string braces" strings: $marker = { 43 55 53 54 4F 4D 48 45 58 } condition: $marker }',
        'rule CustomComment { /* } tricky { */ meta: description = "comment braces" strings: $marker = "CUSTOMCOMMENTMARKER" condition: $marker }',
        'rule CustomRegex { meta: description = "regex braces" strings: $marker = /CUSTOMRE{2}GEX/ condition: $marker }',
    ]
    f = tempwordlist(rule_file)
    config_overrides = {"modules": {"excavate": {"custom_yara_rules": f}}}

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html><body>"
            "<p>CUSTOMBRACEMARKER</p>"
            "<p>CUSTOMSPACEMARKER</p>"
            "<p>CUSTOMHEX</p>"
            "<p>CUSTOMCOMMENTMARKER</p>"
            "<p>CUSTOMREEGEX</p>"
            "</body></html>"
        )

    def check(self, module_test, events):
        # every rule in the file must have been loaded, not just the ones the old splitter survived
        expected = [
            "CustomBraceInString",
            "CustomTwoSpaces",
            "CustomHexString",
            "CustomComment",
            "CustomRegex",
        ]
        loaded = module_test.scan.modules["excavate"].yara_rules_dict
        for rule_name in expected:
            assert rule_name in loaded, f"Rule {rule_name} was dropped by the rule splitter"

        descriptions = [e.data["description"] for e in events if e.type == "FINDING"]
        for rule_name in expected:
            assert any(f"[{rule_name}]" in d for d in descriptions), (
                f"Rule {rule_name} loaded but produced no FINDING, got: {descriptions}"
            )


class TestExcavateYaraConfidence(ModuleTestBase):
    """Test YARA rules with confidence options."""

    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http"]

    async def setup_before_prep(self, module_test):
        yara_test_html = """
        <html><body>
            <p>CONFIRMED_SECRET_DATA</p>
            <p>HIGH_CONFIDENCE_INDICATOR</p>
            <p>MODERATE_RISK_PATTERN</p>
            <p>LOW_CONFIDENCE_MATCH</p>
            <p>UNKNOWN_PATTERN_TYPE</p>
        </body></html>
        """
        module_test.httpserver.expect_request("/").respond_with_data(yara_test_html)

    async def setup_after_prep(self, module_test):
        excavate_module = module_test.scan.modules["excavate"]
        excavateruleinstance = excavateTestRule(excavate_module)

        # Add YARA rules with different confidence levels
        yara_rules = {
            "ConfirmedRule": 'rule ConfirmedRule { meta: description = "Confirmed rule" severity = "HIGH" confidence = "CONFIRMED" strings: $text = "CONFIRMED_SECRET_DATA" condition: $text }',
            "HighConfidenceRule": 'rule HighConfidenceRule { meta: description = "High confidence rule" severity = "MEDIUM" confidence = "HIGH" strings: $text = "HIGH_CONFIDENCE_INDICATOR" condition: $text }',
            "ModerateConfidenceRule": 'rule ModerateConfidenceRule { meta: description = "Moderate confidence rule" severity = "LOW" confidence = "MEDIUM" strings: $text = "MODERATE_RISK_PATTERN" condition: $text }',
            "LowConfidenceRule": 'rule LowConfidenceRule { meta: description = "Low confidence rule" severity = "INFO" confidence = "LOW" strings: $text = "LOW_CONFIDENCE_MATCH" condition: $text }',
            "UnknownConfidenceRule": 'rule UnknownConfidenceRule { meta: description = "Unknown confidence rule" severity = "INFO" confidence = "UNKNOWN" strings: $text = "UNKNOWN_PATTERN_TYPE" condition: $text }',
        }

        for rule_name, rule_content in yara_rules.items():
            excavate_module.add_yara_rule(rule_name, rule_content, excavateruleinstance)

        excavate_module.yara_rules = yara.compile(source="\n".join(excavate_module.yara_rules_dict.values()))

    def check(self, module_test, events):
        """Verify findings are created with correct confidence levels."""
        findings = [e for e in events if e.type == "FINDING"]
        confidence_findings = {f.data.get("confidence", "UNKNOWN"): f for f in findings}

        # Verify all confidence levels are present
        expected_confidences = ["CONFIRMED", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        for confidence in expected_confidences:
            assert confidence in confidence_findings, f"Missing finding with confidence: {confidence}"
            finding = confidence_findings[confidence]
            assert finding.data["confidence"] == confidence
            assert f"confidence-{confidence.lower()}" in finding.tags


class TestExcavateSpiderDedupe(ModuleTestBase):
    class DummyModule(BaseModule):
        watched_events = ["URL_UNVERIFIED"]
        _name = "dummy_module"

        events_seen = []

        async def handle_event(self, event):
            await self.helpers.sleep(0.5)
            self.events_seen.append(event.url)
            new_event = self.scan.make_event(event.data, "URL_UNVERIFIED", self.scan.root_event)
            if new_event is not None:
                await self.emit_event(new_event)

    dummy_text = "<a href='/spider'>spider</a>"
    modules_overrides = ["excavate", "http"]
    targets = [f"{HTTPSERVER_URL}/"]
    config_overrides = {"omit_event_types": []}

    async def setup_after_prep(self, module_test):
        self.dummy_module = self.DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module"] = self.dummy_module
        module_test.httpserver.expect_request("/").respond_with_data(self.dummy_text)
        module_test.httpserver.expect_request("/spider").respond_with_data("hi")

    def check(self, module_test, events):
        found_url_unverified_spider_max = False
        found_url_unverified_dummy = False
        found_url_event = False

        assert sorted(self.dummy_module.events_seen) == [f"{HTTPSERVER_URL}/", f"{HTTPSERVER_URL}/spider"]

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.url == f"{HTTPSERVER_URL}/spider":
                    if str(e.module) == "excavate" and "spider-danger" in e.tags and "spider-max" in e.tags:
                        found_url_unverified_spider_max = True
                    if (
                        str(e.module) == "dummy_module"
                        and "spider-danger" not in e.tags
                        and "spider-max" not in e.tags
                    ):
                        found_url_unverified_dummy = True
            if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/spider":
                found_url_event = True

        assert found_url_unverified_spider_max, "Excavate failed to find /spider link"
        assert found_url_unverified_dummy, "Dummy module did not correctly re-emit"
        assert found_url_event, "URL was not emitted from non-spider-max URL_UNVERIFIED"


class TestExcavateParameterExtraction_targeturl(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/?foo=1"]
    modules_overrides = ["http", "excavate", "hunt"]
    config_overrides = {
        "url_querystring_remove": False,
        "url_querystring_collapse": False,
        "interactsh_disable": True,
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/", "query_string": "foo=1"}
        respond_args = {
            "response_data": "<html>alive</html>",
            "status": 200,
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        web_parameter_emit = False
        for e in events:
            if e.type == "WEB_PARAMETER" and "HTTP Extracted Parameter [foo] (Target URL)" in e.data["description"]:
                web_parameter_emit = True

        assert web_parameter_emit


class TestExcavate_retain_querystring(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/?foo=1"]
    modules_overrides = ["http", "excavate", "hunt"]
    config_overrides = {
        "url_querystring_remove": False,
        "url_querystring_collapse": False,
        "interactsh_disable": True,
        "web": {"spider_distance": 4, "spider_depth": 4},
    }

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/", "query_string": "foo=1"}
        respond_args = {
            "response_data": "<html>alive</html>",
            "headers": {"Set-Cookie": "a=b"},
            "status": 200,
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        web_parameter_emit = False
        for e in events:
            if e.type == "WEB_PARAMETER" and "foo" in e.data["url"]:
                web_parameter_emit = True

        assert web_parameter_emit


class TestExcavate_retain_querystring_not(TestExcavate_retain_querystring):
    config_overrides = {
        "url_querystring_remove": True,
        "url_querystring_collapse": False,
        "interactsh_disable": True,
        "web": {"spider_distance": 4, "spider_depth": 4},
    }

    def check(self, module_test, events):
        web_parameter_emit = False
        for e in events:
            if e.type == "WEB_PARAMETER" and "foo" not in e.data["url"]:
                web_parameter_emit = True

        assert web_parameter_emit


class TestExcavate_webparameter_outofscope(ModuleTestBase):
    html_body = "<html><a class=button href='https://socialmediasite.com/send?text=foo'><a class=button href='https://outofscope.com/send?text=foo'></html>"

    targets = [HTTPSERVER_URL, "socialmediasite.com"]
    modules_overrides = ["http", "excavate", "hunt"]
    config_overrides = {"interactsh_disable": True}

    async def setup_after_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {
            "response_data": self.html_body,
            "status": 200,
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        web_parameter_differentsite = False
        web_parameter_outofscope = False

        for e in events:
            if e.type == "WEB_PARAMETER" and "in-scope" in e.tags and e.host == "socialmediasite.com":
                web_parameter_differentsite = True

            if e.type == "WEB_PARAMETER" and e.host == "outofscope.com":
                web_parameter_outofscope = True

        assert web_parameter_differentsite, "WEB_PARAMETER was not emitted"
        assert not web_parameter_outofscope, "Out of scope domain was emitted"


class TestExcavate_webparameter_ip_host(ModuleTestBase):
    """Verify that when the httpx binary resolves a hostname to an IP (data["host"]),
    excavate still uses the URL hostname for WEB_PARAMETER host — not the resolved IP.

    This test uses 'localhost' as the target. The httpx binary resolves it to 127.0.0.1
    and sets data["host"] = "127.0.0.1" in its JSON output. Without the archive_url guard
    in _event_host(), this IP would be used as the WEB_PARAMETER host, putting it out of
    scope and preventing downstream modules (like lightfuzz) from processing it.
    """

    targets = [LOCALHOST_URL]
    modules_overrides = ["http", "excavate", "hunt"]
    config_overrides = {"interactsh_disable": True}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"localhost": {"A": ["127.0.0.1"]}})
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html><p>hello</p></html>",
            status=200,
            headers={"Set-Cookie": "session=abc123; Path=/"},
        )

    def check(self, module_test, events):
        web_params = [e for e in events if e.type == "WEB_PARAMETER" and e.data["name"] == "session"]
        assert len(web_params) > 0, "WEB_PARAMETER for 'session' cookie was not emitted"
        for wp in web_params:
            assert wp.data["host"] != "127.0.0.1", (
                "WEB_PARAMETER host should be 'localhost', not the resolved IP '127.0.0.1'. "
                "excavate._event_host() is using data['host'] (resolved IP) instead of event.host"
            )
            assert wp.data["host"] == "localhost", f"WEB_PARAMETER host should be 'localhost', got '{wp.data['host']}'"


class TestExcavateHeaders(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http", "hunt"]
    config_overrides = {"web": {"spider_distance": 1, "spider_depth": 1}}

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html><p>test</p></html>",
            status=200,
            headers={
                "Set-Cookie": [
                    "COOKIE1=aaaa; Secure; HttpOnly",
                    "COOKIE2=bbbb; Secure; HttpOnly; SameSite=None",
                ]
            },
        )

    def check(self, module_test, events):
        found_first_cookie = False
        found_second_cookie = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if e.data["name"] == "COOKIE1":
                    found_first_cookie = True
                if e.data["name"] == "COOKIE2":
                    found_second_cookie = True

        assert found_first_cookie is True
        assert found_second_cookie is True


class TestExcavateRAWTEXT(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/", "test.notreal"]
    modules_overrides = ["excavate", "http", "filedownload", "kreuzberg"]
    config_overrides = {
        "scope": {"report_distance": 1},
        "web": {"spider_distance": 2, "spider_depth": 2},
        "modules": {
            "filedownload": {"output_folder": str(bbot_test_dir / "filedownload")},
        },
        "omit_event_types": [],
    }

    pdf_data = r"""%PDF-1.3
%���� ReportLab Generated PDF document http://www.reportlab.com
1 0 obj
<<
/F1 2 0 R
>>
endobj
2 0 obj
<<
/BaseFont /Helvetica /Encoding /WinAnsiEncoding /Name /F1 /Subtype /Type1 /Type /Font
>>
endobj
3 0 obj
<<
/Contents 7 0 R /MediaBox [ 0 0 595.2756 841.8898 ] /Parent 6 0 R /Resources <<
/Font 1 0 R /ProcSet [ /PDF /Text /ImageB /ImageC /ImageI ]
>> /Rotate 0 /Trans <<

>>
  /Type /Page
>>
endobj
4 0 obj
<<
/PageMode /UseNone /Pages 6 0 R /Type /Catalog
>>
endobj
5 0 obj
<<
/Author (anonymous) /CreationDate (D:20240807182842+00'00') /Creator (ReportLab PDF Library - www.reportlab.com) /Keywords () /ModDate (D:20240807182842+00'00') /Producer (ReportLab PDF Library - www.reportlab.com)
  /Subject (unspecified) /Title (untitled) /Trapped /False
>>
endobj
6 0 obj
<<
/Count 1 /Kids [ 3 0 R ] /Type /Pages
>>
endobj
7 0 obj
<<
/Filter [ /ASCII85Decode /FlateDecode ] /Length 742
>>
stream
Gas2F;0/Hc'SYHA/+V9II1V!>b>-epMEjN4$Udfu3WXha!?H`crq_UNGP5IS$'WT'SF]Hm/eEhd_JY>@!1knV$j`L/E!kN:0EQJ+FF:uKph>GV#ju48hu\;DS#c\h,:/udaV^[@;X>;"'ep>>)(B?I-n?2pLTEZKb$BFgKRF(b#Pc?SYeqN_Q<+X%64E)"g-fPCbq][OcNlQLW_hs%Z%g83]3b]0V$sluS:l]fd*^-UdD=#bCpInTen.cfe189iIh6\.p.U0GF:oK9b'->\lOqObp&ppaGMoCcp"4SVDq!<>6ZV]FD>,rrdc't<[N2!Ai12-2<OHlF74n#8(/WCG7Tai2$(/r@ULUNdEZ3Op<HV;A-c0GnY'M+s]&p&%@CgEr<@Bc.Uf<HojGCuBU=*pA.;2`iCVN!R2W:7h`/$bDaRRVeOY>bU`S*gNOt?NS4WgtN@KuL)HOb>`9L>S$_ert"UNW*,("+*>]m)4`k"8SUOCpM7`cEe!(7?`JV*GMajff(^atd&EX#qdMBmI'Q(YYb&m.O>0MYJ4XfJH@("`jPF^W5.*84$HY?2JY[WU48,IqkD_]b:_615)BA3RM*]q4>2Gf_1aMGFGu.Zt]!p5h;`XYO/FCmQ4/3ZX09kH$X+QI/JJh`lb\dBu:d$%Ld1=H=-UbKXP_&26H00T.?":f@40#m]NM5JYq@VFSk+#OR+sc4eX`Oq]N([T/;kQ>>WZOJNWnM"#msq:#?Km~>endstream
endobj
xref
0 8
0000000000 65535 f
0000000073 00000 n
0000000104 00000 n
0000000211 00000 n
0000000414 00000 n
0000000482 00000 n
0000000778 00000 n
0000000837 00000 n
trailer
<<
/ID
[<3c7340500fa2fe72523c5e6f07511599><3c7340500fa2fe72523c5e6f07511599>]
% ReportLab generated PDF document -- digest (http://www.reportlab.com)

/Info 5 0 R
/Root 4 0 R
/Size 8
>>
startxref
1669
%%EOF"""
    kreuzberg_response = "This is an email example@blacklanternsecurity.notreal An example JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c A serialized DOTNET object AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5TdHJpbmddXSwgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGFlMwEAAAAIQ29tcGFyZXIQSXRlbUNvdW50AQMAAAAJAwAAAAlTeXN0ZW0uU3RyaW5nW10FAAAACQIAAAAJBAAAAAkFAAAACRcAAAAJCgAAAAkLAAAACQwAAAAJDQAAAAkOAAAACQ8AAAAJEAAAAAkRAAAACRIAAAAJEwAAAA== A full url https://www.test.notreal/about A href <a href='/donot_detect.js'>Click me</a>"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            {"uri": "/"},
            {"response_data": '<a href="/Test_PDF"/>'},
        )
        module_test.set_expect_requests(
            {"uri": "/Test_PDF"},
            {"response_data": self.pdf_data, "headers": {"Content-Type": "application/pdf"}},
        )

    def check(self, module_test, events):
        filesystem_events = [e for e in events if e.type == "FILESYSTEM"]
        assert 1 == len(filesystem_events), filesystem_events
        filesystem_event = filesystem_events[0]
        file = Path(filesystem_event.data["path"])
        assert file.is_file(), "Destination file doesn't exist"
        assert open(file).read() == self.pdf_data, f"File at {file} does not contain the correct content"
        raw_text_events = [e for e in events if e.type == "RAW_TEXT"]
        assert 1 == len(raw_text_events), "Failed to emit RAW_TEXT event"
        assert raw_text_events[0].data == self.kreuzberg_response, (
            f"Text extracted from PDF is incorrect, got {raw_text_events[0].data}"
        )
        email_events = [e for e in events if e.type == "EMAIL_ADDRESS"]
        assert 1 == len(email_events), "Failed to emit EMAIL_ADDRESS event"
        assert email_events[0].data == "example@blacklanternsecurity.notreal", (
            f"Email extracted from kreuzberg text is incorrect, got {email_events[0].data}"
        )
        finding_events = [e for e in events if e.type == "FINDING"]
        assert 2 == len(finding_events), "Failed to emit FINDING events"
        assert any(
            e.type == "FINDING"
            and "JWT" in e.data["description"]
            and e.data["url"] == f"{HTTPSERVER_URL}/Test_PDF"
            and e.data["host"] == "127.0.0.1"
            and e.data["path"].endswith(f"http-127-0-0-1-{HTTPSERVER_PORT}-test-pdf.pdf")
            and str(e.host) == "127.0.0.1"
            for e in finding_events
        ), f"Failed to emit JWT event got {finding_events}"
        assert any(
            e.type == "FINDING"
            and "DOTNET" in e.data["description"]
            and e.data["url"] == f"{HTTPSERVER_URL}/Test_PDF"
            and e.data["host"] == "127.0.0.1"
            and e.data["path"].endswith(f"http-127-0-0-1-{HTTPSERVER_PORT}-test-pdf.pdf")
            and str(e.host) == "127.0.0.1"
            for e in finding_events
        ), f"Failed to emit serialized event got {finding_events}"
        assert finding_events[0].data["path"] == str(file), "File path not included in finding event"
        url_events = [e.pretty_string for e in events if e.type == "URL_UNVERIFIED"]
        assert "https://www.test.notreal/about" in url_events, (
            f"URL extracted from kreuzberg text is incorrect, got {url_events}"
        )
        assert "/donot_detect.js" not in url_events, (
            f"URL extracted from kreuzberg text is incorrect, got {url_events}"
        )


class TestExcavateHeaders_blacklist(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http", "hunt"]
    config_overrides = {"web": {"spider_distance": 1, "spider_depth": 1}}

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "<html><p>test</p></html>",
            status=200,
            headers={
                "Set-Cookie": [
                    "COOKIE1=aaaa; Secure; HttpOnly",
                    "TS0113CC91=bbbb; Secure; HttpOnly; SameSite=None",
                    "PHPSESSID=cccc; Secure; HttpOnly; SameSite=None",
                ]
            },
        )

    def check(self, module_test, events):
        found_first_cookie = False
        found_second_cookie = False
        found_third_cookie = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if e.data["name"] == "COOKIE1":
                    found_first_cookie = True
                if e.data["name"] == "PHPSESSID":
                    found_second_cookie = True
                if e.data["name"] == "TS0113CC91":
                    found_third_cookie = True

        assert found_first_cookie is True
        assert found_second_cookie is False
        assert found_third_cookie is False


class TestExcavateBadURLs(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http", "hunt"]
    config_overrides = {"interactsh_disable": True, "scope": {"report_distance": 10}, "omit_event_types": []}

    bad_url_data = """
<a href='mailto:bob@evilcorp.org?subject=help'>Help</a>
<a href='https://ssl.'>Help</a>
"""

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": self.bad_url_data})

    def check(self, module_test, events):
        import gzip

        debug_log_content = open(module_test.scan.home / "debug.log").read()
        for archived_debug_log in module_test.scan.home.glob("debug.log.*.gz"):
            gzipped_content = open(archived_debug_log).read()
            ungzipped_content = gzip.decompress(gzipped_content).decode("utf-8")
            debug_log_content += ungzipped_content

        # make sure our logging is working
        assert "Setting scan status to RUNNING" in debug_log_content
        # make sure we don't have any URL validation errors
        assert "Error Parsing reconstructed URL" not in debug_log_content
        assert "Error sanitizing event data" not in debug_log_content

        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        assert sorted([e.pretty_string for e in url_events]) == sorted(["https://ssl/", f"{HTTPSERVER_URL}/"])


class TestExcavateURL_InvalidPort(TestExcavate):
    modules_overrides = ["excavate", "http", "hunt"]

    async def setup_before_prep(self, module_test):
        # Test URL with invalid port (greater than 65535)
        module_test.httpserver.expect_request("/").respond_with_data(
            '<div><img loading="lazy" src="https://asdffoo.test.notreal:9212952841/whatever.jpg" width="576" height="382" alt="...." /></div>'
        )

    def check(self, module_test, events):
        # Verify we got the hostname
        assert any(e.data == "asdffoo.test.notreal" for e in events)


class TestExcavateIgnorePDF(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["excavate", "http"]

    # body content that would normally produce findings if processed
    pdf_body_with_urls = "https://pdf-extracted.test.notreal/some/path ftp://ftp.test.notreal"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            {"uri": "/"},
            {"response_data": self.pdf_body_with_urls, "headers": {"Content-Type": "application/pdf"}},
        )

    def check(self, module_test, events):
        # excavate should skip PDF responses entirely, so no URLs or findings should be extracted from the body
        url_unverified_events = [
            e for e in events if e.type == "URL_UNVERIFIED" and "pdf-extracted.test.notreal" in e.url
        ]
        assert len(url_unverified_events) == 0, (
            f"PDF body should not be processed by excavate, but got: {url_unverified_events}"
        )

        ftp_findings = [
            e for e in events if e.type == "FINDING" and "ftp://ftp.test.notreal" in e.data.get("description", "")
        ]
        assert len(ftp_findings) == 0, f"PDF body should not produce findings, but got: {ftp_findings}"


class TestExcavateRedirectParameterScope(ModuleTestBase):
    """Verify that parameter extraction is skipped for out-of-scope redirect targets.

    When an in-scope HTTP response has a Location header pointing to an external
    out-of-scope domain, the redirect URL's query parameters should NOT be emitted
    as WEB_PARAMETER events, because they would inherit the in-scope parent's scope
    distance and cause lightfuzz to fuzz external endpoints.
    """

    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "hunt"]

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "",
            status=302,
            headers={"Location": "https://login.microsoftonline.com/oauth2/authorize?state=abc123&client_id=test456"},
        )

    def check(self, module_test, events):
        # The redirect URL itself should be emitted as URL_UNVERIFIED (that's correct behavior)
        assert any(e.type == "URL_UNVERIFIED" and "login.microsoftonline.com" in e.url for e in events), (
            "Redirect URL_UNVERIFIED should still be emitted"
        )

        # But NO WEB_PARAMETER events should be emitted for the out-of-scope redirect's parameters
        redirect_params = [
            e for e in events if e.type == "WEB_PARAMETER" and "login.microsoftonline.com" in e.data.get("url", "")
        ]
        assert len(redirect_params) == 0, (
            f"Out-of-scope redirect parameters should not be extracted, but got: {redirect_params}"
        )


# Verifies excavate extracts parameters from a form whose body is far larger than
# YARA's `.*` regex ceiling (~4 KB). The fix routes form discovery through an
# opening-tag-only YARA regex and reads the form body from a bounded slice of the
# response. Before the fix, this fixture produced zero WEB_PARAMETER events; after
# it, every field must be extracted, and the work must stay fast.
class TestExcavateGiantForm(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "hunt"]

    GIANT_OPTION_COUNT = 5000

    @classmethod
    def _build_giant_form_html(cls, option_count):
        # ~40 bytes per option × N options dominates the form body, easily blowing
        # past YARA's regex ceiling on `<form>.*</form>` patterns.
        options = "".join(f'<option value="OPT_{i:05d}">label {i:05d}</option>' for i in range(option_count))
        return (
            "<html><body>"
            '<form action="/giant-submit" method="post">'
            '<input type="hidden" name="csrf" value="abc123">'
            '<input type="text" name="search_term" value="">'
            f'<select name="provider_id">{options}</select>'
            '<input type="submit" value="go">'
            "</form>"
            "</body></html>"
        )

    async def setup_after_prep(self, module_test):
        body = self._build_giant_form_html(self.GIANT_OPTION_COUNT)
        # Sanity check the fixture really is past the YARA cliff.
        assert len(body) > 100_000, f"giant-form fixture not large enough: {len(body)} bytes"
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": body, "status": 200, "headers": {"Content-Type": "text/html"}},
        )
        # Stash a start time so check() can do a coarse wall-clock assertion.
        module_test._giantform_start = time.monotonic()

    def check(self, module_test, events):
        elapsed = time.monotonic() - module_test._giantform_start
        # Coarse upper bound: full scan including HTTP fetch should stay snappy on
        # a normal dev box even with a 200 KB form. The spec calls for sub-200ms
        # processing of the giant-form HTTP_RESPONSE itself; we allow more slack
        # here because the wall-clock includes the rest of the scan harness.
        assert elapsed < 30, f"giant-form scan took {elapsed:.1f}s — likely a pathological regex regression"

        web_params = {e.data.get("name") for e in events if e.type == "WEB_PARAMETER" and isinstance(e.data, dict)}
        expected = {"provider_id", "csrf", "search_term"}
        missing = expected - web_params
        assert not missing, f"WEB_PARAMETERs missing for giant-form fields: {missing}. Got: {sorted(web_params)}"


# Same shape as the giant-form test but with a form body that exceeds
# max_form_bytes. The bound is a defensive cap: forms that don't fit are
# skipped entirely (no partial extraction). The test asserts excavate doesn't
# hang or OOM on a multi-hundred-KB form fixture.
class TestExcavateGiantFormExceedsMaxBytes(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "hunt"]

    # Constrain max_form_bytes so we don't have to generate a literal 2 MB
    # fixture to prove the bound holds — 32 KB is well below the body size
    # the next fixture generates (~240 KB).
    config_overrides = {"modules": {"excavate": {"max_form_bytes": 32768}}}

    OPTION_COUNT = 6000  # ~240 KB form body — 7.5× past max_form_bytes

    @classmethod
    def _build_giant_form_html(cls, option_count):
        options = "".join(f'<option value="OPT_{i:05d}">label {i:05d}</option>' for i in range(option_count))
        return (
            "<html><body>"
            '<form action="/giant-submit" method="post">'
            '<input type="hidden" name="csrf" value="abc123">'
            '<input type="text" name="search_term" value="">'
            f'<select name="provider_id">{options}</select>'
            '<input type="submit" value="go">'
            "</form>"
            "</body></html>"
        )

    async def setup_after_prep(self, module_test):
        body = self._build_giant_form_html(self.OPTION_COUNT)
        # Sanity check we built something that actually exceeds the configured bound.
        assert len(body) > 32768 * 5, f"oversized fixture too small: {len(body)} bytes"
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": body, "status": 200, "headers": {"Content-Type": "text/html"}},
        )
        module_test._oversized_start = time.monotonic()

    def check(self, module_test, events):
        # Hang/OOM guard: a runaway extractor would push wall-clock well past
        # this. A correctly-bounded extractor handles even a 240 KB form in seconds.
        elapsed = time.monotonic() - module_test._oversized_start
        assert elapsed < 60, f"oversized-form scan took {elapsed:.1f}s — bound likely not enforced"

        # No form-field WEB_PARAMETERs should be emitted for the oversized form
        # — extraction regex anchors on `</form>` which falls outside the bound.
        # Other WEB_PARAMETERs (e.g. global `test` header from scan config) are fine.
        form_fields = {"csrf", "search_term", "provider_id"}
        emitted = {e.data.get("name") for e in events if e.type == "WEB_PARAMETER" and isinstance(e.data, dict)}
        leaked = form_fields & emitted
        assert not leaked, (
            f"oversized form's fields should be skipped entirely under the bound, but excavate emitted: {leaked}"
        )


# Verifies the opening-tag YARA regex fires regardless of attribute order.
# Both `<form action=X method=post>` and `<form method=post action=X>` should
# extract the form's fields.
class TestExcavateFormAttributeOrder(ModuleTestBase):
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["http", "excavate", "hunt"]

    html = """
    <html><body>
    <form action="/submit1" method="post">
        <input type="text" name="action_first" value="v1">
    </form>
    <form method="post" action="/submit2">
        <input type="text" name="method_first" value="v2">
    </form>
    </body></html>
    """

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": self.html, "status": 200, "headers": {"Content-Type": "text/html"}},
        )

    def check(self, module_test, events):
        names = {e.data.get("name") for e in events if e.type == "WEB_PARAMETER" and isinstance(e.data, dict)}
        assert "action_first" in names, f"missing action-first form field; got {sorted(names)}"
        assert "method_first" in names, f"missing method-first form field; got {sorted(names)}"


class TestExcavateHttpWildcardSkipsUrls(ModuleTestBase):
    """On an HTTP wildcard host, excavate should suppress URL_UNVERIFIED but still extract DNS_NAMEs."""

    targets = [f"{HTTPSERVER_URL}/", "test.notreal"]
    modules_overrides = ["excavate", "http"]
    config_overrides = {"web": {"spider_distance": 1, "spider_depth": 1}}

    html_body = f"""
    <a href="{HTTPSERVER_URL}/should-be-suppressed">link</a>
    bare hostname: extracted.test.notreal
    """

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": self.html_body, "status": 200},
        )

    async def setup_after_prep(self, module_test):
        async def mock_wildcard(scheme, host, port):
            if host == "127.0.0.1":
                return True
            return False

        module_test.scan.helpers.web.is_http_wildcard_host = mock_wildcard
        await module_test.mock_dns({"extracted.test.notreal": {"A": ["127.0.0.88"]}})

    def check(self, module_test, events):
        excavate_urls = [
            e
            for e in events
            if e.type == "URL_UNVERIFIED" and str(e.module) == "excavate" and "should-be-suppressed" in e.url
        ]
        assert len(excavate_urls) == 0, (
            f"Excavate should suppress URL_UNVERIFIED on HTTP wildcard host, got: {[e.url for e in excavate_urls]}"
        )
        assert any(e.type == "DNS_NAME" and e.data == "extracted.test.notreal" for e in events), (
            "Excavate should still extract DNS_NAMEs from HTTP wildcard host responses"
        )


class TestExcavateContentDedup(ModuleTestBase):
    """Verify _avoid_duplicate_content=True on excavate skips HTTP_RESPONSE events with duplicate body hashes."""

    targets = [
        f"{HTTPSERVER_URL}/dir1/page.html",
        f"{HTTPSERVER_URL}/dir2/page.html",
        f"{HTTPSERVER_URL}/other/page.html",
    ]
    modules_overrides = ["excavate", "http"]
    config_overrides = {"web": {"spider_distance": 0, "spider_depth": 0}, "omit_event_types": []}

    duplicate_body = "<html><body><a href='./found.html'>click</a></body></html>"
    unique_body = "<html><body><a href='./unique.html'>click</a></body></html>"

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/dir1/page.html"},
            respond_args={"response_data": self.duplicate_body},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/dir2/page.html"},
            respond_args={"response_data": self.duplicate_body},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/other/page.html"},
            respond_args={"response_data": self.unique_body},
        )
        module_test.httpserver.no_handler_status_code = 404

    def check(self, module_test, events):
        excavate = module_test.scan.modules["excavate"]
        assert len(excavate._content_dup_tracker) > 0, "Content dedup tracker was empty"

        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        urls = {e.url for e in url_events}

        assert f"{HTTPSERVER_URL}/other/unique.html" in urls, "Unique page link not extracted"

        dir1_found = f"{HTTPSERVER_URL}/dir1/found.html" in urls
        dir2_found = f"{HTTPSERVER_URL}/dir2/found.html" in urls
        assert dir1_found or dir2_found, "Neither duplicate page was processed"
        assert not (dir1_found and dir2_found), (
            "Both duplicate pages were processed — content dedup failed to skip the second one"
        )


class TestExcavateContentDedupDisabled(ModuleTestBase):
    """Verify that with _avoid_duplicate_content=False, duplicate content on different URLs is NOT deduped."""

    targets = [
        f"{HTTPSERVER_URL}/dir1/page.html",
        f"{HTTPSERVER_URL}/dir2/page.html",
    ]
    modules_overrides = ["excavate", "http"]
    config_overrides = {"web": {"spider_distance": 0, "spider_depth": 0}, "omit_event_types": []}

    duplicate_body = "<html><body><a href='./found.html'>click</a></body></html>"

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/dir1/page.html"},
            respond_args={"response_data": self.duplicate_body},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/dir2/page.html"},
            respond_args={"response_data": self.duplicate_body},
        )
        module_test.httpserver.no_handler_status_code = 404

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["excavate"]._avoid_duplicate_content = False

    def check(self, module_test, events):
        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        urls = {e.url for e in url_events}

        dir1_found = f"{HTTPSERVER_URL}/dir1/found.html" in urls
        dir2_found = f"{HTTPSERVER_URL}/dir2/found.html" in urls
        assert dir1_found and dir2_found, (
            f"Both duplicate pages should be processed when _avoid_duplicate_content=False, "
            f"got dir1={dir1_found}, dir2={dir2_found}"
        )


class TestContentDedupWithURLEvents(ModuleTestBase):
    """Verify _avoid_duplicate_content works for modules watching URL events (via body_sha256 hash)."""

    targets = [
        f"{HTTPSERVER_URL}/page1.html",
        f"{HTTPSERVER_URL}/page2.html",
        f"{HTTPSERVER_URL}/different.html",
    ]
    modules_overrides = ["excavate", "http"]
    config_overrides = {"web": {"spider_distance": 0, "spider_depth": 0}, "omit_event_types": []}

    duplicate_body = "<html><body>identical content</body></html>"
    unique_body = "<html><body>different content</body></html>"

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/page1.html"},
            respond_args={"response_data": self.duplicate_body},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/page2.html"},
            respond_args={"response_data": self.duplicate_body},
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/different.html"},
            respond_args={"response_data": self.unique_body},
        )
        module_test.httpserver.no_handler_status_code = 404

    async def setup_after_prep(self, module_test):
        class URLConsumer(BaseModule):
            watched_events = ["URL"]
            _name = "url_consumer"
            _avoid_duplicate_content = True
            events_seen = []

            async def handle_event(self, event):
                self.events_seen.append(event)

        module_test.scan.modules["url_consumer"] = URLConsumer(module_test.scan)

    def check(self, module_test, events):
        consumer = module_test.scan.modules["url_consumer"]
        seen_urls = {e.url for e in consumer.events_seen if e.type == "URL"}

        assert f"{HTTPSERVER_URL}/different.html" in seen_urls, "Unique URL should be processed"

        page1_seen = f"{HTTPSERVER_URL}/page1.html" in seen_urls
        page2_seen = f"{HTTPSERVER_URL}/page2.html" in seen_urls
        assert page1_seen or page2_seen, "At least one duplicate-content URL should be processed"
        assert not (page1_seen and page2_seen), (
            "Both duplicate-content URLs were processed — content dedup failed for URL events"
        )
        assert len(consumer._content_dup_tracker) > 0, "Content dedup tracker should have entries"
