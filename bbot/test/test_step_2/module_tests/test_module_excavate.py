from ...bbot_fixtures import *
from bbot.modules.base import BaseModule
from .base import ModuleTestBase, tempwordlist

from bbot.modules.internal.excavate import ExcavateRule

from pathlib import Path
import yara


class TestExcavate(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/", "test.notreal", "http://127.0.0.1:8888/subdir/links.html"]
    modules_overrides = ["excavate", "httpx"]
    config_overrides = {"web": {"spider_distance": 1, "spider_depth": 1}}

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
        # these ones shouldn't get emitted because they're .js (url_extension_httpx_only)
        <a href="/a_relative.js">
        <link href="/link_relative.js">
        # these ones should
        <a href="/a_relative.txt">
        <link href="/link_relative.txt">
        <a href="mailto:bob@evilcorp.org?subject=help">Help</a>
        <li class="toctree-l3"><a class="reference internal" href="miscellaneous.html#x50-uart-driver">16x50 UART Driver</a></li>
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

    def check(self, module_test, events):
        event_data = [e.data for e in events]
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
        assert "http://127.0.0.1:8888/a_relative.js" not in event_data
        assert "http://127.0.0.1:8888/link_relative.js" not in event_data
        assert "http://127.0.0.1:8888/a_relative.txt" in event_data
        assert "http://127.0.0.1:8888/link_relative.txt" in event_data

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
            and e.data == "http://127.0.0.1:8888/relative.html"
            and "spider-max" not in e.tags
            and "endpoint" in e.tags
            and "extension-html" in e.tags
            and "in-scope" in e.tags
            and e.scope_distance == 0
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/2/depth2.html" and "spider-max" in e.tags
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/distance2.html" and "spider-max" in e.tags
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED" and "miscellaneous.html" in e.data and "x50-uart-driver" not in e.data
            for e in events
        )


class TestExcavate2(TestExcavate):
    targets = ["http://127.0.0.1:8888/", "test.notreal", "http://127.0.0.1:8888/subdir/"]

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
        page_relative_detection_1 = False
        root_page_confusion_1 = False
        root_page_confusion_2 = False

        for e in events:
            if e.type == "URL_UNVERIFIED":
                # these cases represent the desired behavior for parsing relative links
                if e.data == "http://127.0.0.1:8888/rootrelative.html":
                    root_relative_detection = True
                if e.data == "http://127.0.0.1:8888/subdir/pagerelative1.html":
                    page_relative_detection_1 = True
                if e.data == "http://127.0.0.1:8888/subdir/pagerelative2.html":
                    page_relative_detection_2 = True

                # these cases indicates that excavate parsed the relative links incorrectly
                if e.data == "http://127.0.0.1:8888/pagerelative.html":
                    root_page_confusion_1 = True
                if e.data == "http://127.0.0.1:8888/subdir/rootrelative.html":
                    root_page_confusion_2 = True

        assert root_relative_detection, "Failed to properly excavate root-relative URL"
        assert page_relative_detection_1, "Failed to properly excavate page-relative URL"
        assert page_relative_detection_2, "Failed to properly excavate page-relative URL"
        assert not root_page_confusion_1, "Incorrectly detected page-relative URL"
        assert not root_page_confusion_2, "Incorrectly detected root-relative URL"


class TestExcavateRedirect(TestExcavate):
    targets = ["http://127.0.0.1:8888/", "http://127.0.0.1:8888/relative/", "http://127.0.0.1:8888/nonhttpredirect/"]
    config_overrides = {"scope": {"report_distance": 1}}

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
                if e.type == "URL_UNVERIFIED" and e.data == "https://www.test.notreal/yep" and e.scope_distance == 1
            ]
        )
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/relative/owa/"])
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
    targets = ["http://127.0.0.1:8888/"]
    config_overrides = {"url_querystring_remove": True, "url_querystring_collapse": True}
    lots_of_params = """
    <a href="http://127.0.0.1:8888/endpoint?foo=1"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=2"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=3"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=4"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=5"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=6"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=7"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=8"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=9"/>
    <a href="http://127.0.0.1:8888/endpoint?foo=10"/>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.lots_of_params)

    def check(self, module_test, events):
        assert len([e for e in events if e.type == "URL_UNVERIFIED"]) == 2
        assert (
            len([e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/endpoint"]) == 1
        )


class TestExcavateQuerystringRemoveFalse(TestExcavateQuerystringRemoveTrue):
    config_overrides = {"url_querystring_remove": False, "url_querystring_collapse": True}

    def check(self, module_test, events):
        assert (
            len(
                [
                    e
                    for e in events
                    if e.type == "URL_UNVERIFIED" and e.data.startswith("http://127.0.0.1:8888/endpoint?")
                ]
            )
            == 1
        )


class TestExcavateQuerystringCollapseFalse(TestExcavateQuerystringRemoveTrue):
    config_overrides = {"url_querystring_remove": False, "url_querystring_collapse": False}

    def check(self, module_test, events):
        assert (
            len(
                [
                    e
                    for e in events
                    if e.type == "URL_UNVERIFIED" and e.data.startswith("http://127.0.0.1:8888/endpoint?")
                ]
            )
            == 10
        )


class TestExcavateMaxLinksPerPage(TestExcavate):
    targets = ["http://127.0.0.1:8888/"]
    config_overrides = {"web": {"spider_links_per_page": 10, "spider_distance": 1}}

    lots_of_links = """
    <a href="http://127.0.0.1:8888/1"/>
    <a href="http://127.0.0.1:8888/2"/>
    <a href="http://127.0.0.1:8888/3"/>
    <a href="http://127.0.0.1:8888/4"/>
    <a href="http://127.0.0.1:8888/5"/>
    <a href="http://127.0.0.1:8888/6"/>
    <a href="http://127.0.0.1:8888/7"/>
    <a href="http://127.0.0.1:8888/8"/>
    <a href="http://127.0.0.1:8888/9"/>
    <a href="http://127.0.0.1:8888/10"/>
    <a href="http://127.0.0.1:8888/11"/>
    <a href="http://127.0.0.1:8888/12"/>
    <a href="http://127.0.0.1:8888/13"/>
    <a href="http://127.0.0.1:8888/14"/>
    <a href="http://127.0.0.1:8888/15"/>
    <a href="http://127.0.0.1:8888/16"/>
    <a href="http://127.0.0.1:8888/17"/>
    <a href="http://127.0.0.1:8888/18"/>
    <a href="http://127.0.0.1:8888/19"/>
    <a href="http://127.0.0.1:8888/20"/>
    <a href="http://127.0.0.1:8888/21"/>
    <a href="http://127.0.0.1:8888/22"/>
    <a href="http://127.0.0.1:8888/23"/>
    <a href="http://127.0.0.1:8888/24"/>
    <a href="http://127.0.0.1:8888/25"/>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.lots_of_links)

    def check(self, module_test, events):
        url_unverified_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        # base URL + 25 links = 26
        assert len(url_unverified_events) == 26
        url_data = [e.data for e in url_unverified_events if "spider-max" not in e.tags and "spider-danger" in e.tags]
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
        assert any(e.data == "https://asdffoo.test.notreal/some/path" for e in events)


class TestExcavateURL_IP(TestExcavate):
    targets = ["http://127.0.0.1:8888/", "127.0.0.2"]

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data("SomeSMooshedDATAhttps://127.0.0.2/some/path")

    def check(self, module_test, events):
        assert any(e.data == "127.0.0.2" for e in events)
        assert any(e.data == "https://127.0.0.2/some/path" for e in events)


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
    targets = ["http://127.0.0.1:8888/", "test.notreal"]

    non_http_scheme_html = """

    <html>
    <head>
    </head>
    <body>
    <p>hxxp://test.notreal</p>
    <p>ftp://test.notreal</p>
    <p>nonsense://test.notreal</p>
    </body>
    </html>
    """

    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(self.non_http_scheme_html)

    def check(self, module_test, events):
        found_hxxp_url = False
        found_ftp_url = False
        found_nonsense_url = False

        for e in events:
            if e.type == "FINDING":
                if e.data["description"] == "Non-HTTP URI: hxxp://test.notreal":
                    found_hxxp_url = True
                if e.data["description"] == "Non-HTTP URI: ftp://test.notreal":
                    found_ftp_url = True
                if "nonsense" in e.data["description"]:
                    found_nonsense_url = True
        assert found_hxxp_url
        assert found_ftp_url
        assert not found_nonsense_url


class TestExcavateParameterExtraction(TestExcavate):
    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["excavate", "httpx", "hunt"]
    targets = ["http://127.0.0.1:8888/"]
    parameter_extraction_html = """
    <html>
    <head>
        <title>Get extract</title>
        <script>
            $.get("/test", {jqueryget: "value1"});
            $.post("/test", {jquerypost: "value2"});
        </script>
    </head>
    <body>
    <body>
        <h1>Simple GET Form</h1>
        <p>Use the form below to submit a GET request:</p>
        <form action="/search" method="get">
            <label for="searchQuery">Search Query:</label>
            <input type="text" id="searchQuery" name="q" value="flowers"><br><br>
            <input type="submit" value="Search">
        </form>
        <h1>Simple POST Form</h1>
        <p>Use the form below to submit a POST request:</p>
        <form action="/search" method="post">
            <label for="searchQuery">Search Query:</label>
            <input type="text" id="searchQuery" name="q" value="boats"><br><br>
            <input type="submit" value="Search">
        </form>
        <p>Links</p>
        <a href="/validPath?id=123&age=456">href</a>
        <img src="http://127.0.0.1:8888/validPath?size=m&fit=slim">img</a>
    </body>
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
        found_jquery_get_original_value = False
        found_jquery_post_original_value = False
        found_form_get_original_value = False
        found_form_post_original_value = False
        found_htmltags_a = False
        found_htmltags_img = False

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

                if e.data["description"] == "HTTP Extracted Parameter [q] (GET Form Submodule)":
                    found_form_get = True
                    if e.data["original_value"] == "flowers":
                        found_form_get_original_value = True

                if e.data["description"] == "HTTP Extracted Parameter [q] (POST Form Submodule)":
                    found_form_post = True
                    if e.data["original_value"] == "boats":
                        found_form_post_original_value = True

                if e.data["description"] == "HTTP Extracted Parameter [age] (HTML Tags Submodule)":
                    if e.data["original_value"] == "456":
                        if "id" in e.data["additional_params"].keys():
                            found_htmltags_a = True

                if e.data["description"] == "HTTP Extracted Parameter [size] (HTML Tags Submodule)":
                    if e.data["original_value"] == "m":
                        if "fit" in e.data["additional_params"].keys():
                            found_htmltags_img = True

        assert found_jquery_get, "Did not extract Jquery GET parameters"
        assert found_jquery_post, "Did not extract Jquery POST parameters"
        assert found_form_get, "Did not extract Form GET parameters"
        assert found_form_post, "Did not extract Form POST parameters"
        assert found_jquery_get_original_value, "Did not extract Jquery GET parameter original_value"
        assert found_jquery_post_original_value, "Did not extract Jquery POST parameter original_value"
        assert found_form_get_original_value, "Did not extract Form GET parameter original_value"
        assert found_form_post_original_value, "Did not extract Form POST parameter original_value"
        assert found_htmltags_a, "Did not extract parameter(s) from a-tag"
        assert found_htmltags_img, "Did not extract parameter(s) from img-tag"


class TestExcavateParameterExtraction_getparam(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]

    # hunt is added as parameter extraction is only activated by one or more modules that consume WEB_PARAMETER
    modules_overrides = ["httpx", "excavate", "hunt"]
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


class TestExcavateParameterExtraction_json(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["httpx", "excavate", "paramminer_getparams"]
    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist([]), "recycle_words": True}}}
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
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["httpx", "excavate", "paramminer_getparams"]
    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist([]), "recycle_words": True}}}
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


class excavateTestRule(ExcavateRule):
    yara_rules = {
        "SearchForText": 'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
        "SearchForText2": 'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text2 = "DDDDEEEEFFFF" condition: $text2 }',
    }


class TestExcavateYara(TestExcavate):
    targets = ["http://127.0.0.1:8888/"]
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
        self.modules_overrides = ["excavate", "httpx"]
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


class TestExcavateYaraCustom(TestExcavateYara):
    rule_file = [
        'rule SearchForText { meta: description = "Contains the text AAAABBBBCCCC" strings: $text = "AAAABBBBCCCC" condition: $text }',
        'rule SearchForText2 { meta: description = "Contains the text DDDDEEEEFFFF" strings: $text2 = "DDDDEEEEFFFF" condition: $text2 }',
    ]
    f = tempwordlist(rule_file)
    config_overrides = {"modules": {"excavate": {"custom_yara_rules": f}}}


class TestExcavateSpiderDedupe(ModuleTestBase):
    class DummyModule(BaseModule):
        watched_events = ["URL_UNVERIFIED"]
        _name = "dummy_module"

        events_seen = []

        async def handle_event(self, event):
            await self.helpers.sleep(0.5)
            self.events_seen.append(event.data)
            new_event = self.scan.make_event(event.data, "URL_UNVERIFIED", self.scan.root_event)
            if new_event is not None:
                await self.emit_event(new_event)

    dummy_text = "<a href='/spider'>spider</a>"
    modules_overrides = ["excavate", "httpx"]
    targets = ["http://127.0.0.1:8888/"]

    async def setup_after_prep(self, module_test):
        self.dummy_module = self.DummyModule(module_test.scan)
        module_test.scan.modules["dummy_module"] = self.dummy_module
        module_test.httpserver.expect_request("/").respond_with_data(self.dummy_text)
        module_test.httpserver.expect_request("/spider").respond_with_data("hi")

    def check(self, module_test, events):
        found_url_unverified_spider_max = False
        found_url_unverified_dummy = False
        found_url_event = False

        assert sorted(self.dummy_module.events_seen) == ["http://127.0.0.1:8888/", "http://127.0.0.1:8888/spider"]

        for e in events:
            if e.type == "URL_UNVERIFIED":
                if e.data == "http://127.0.0.1:8888/spider":
                    if str(e.module) == "excavate" and "spider-danger" in e.tags and "spider-max" in e.tags:
                        found_url_unverified_spider_max = True
                    if (
                        str(e.module) == "dummy_module"
                        and "spider-danger" not in e.tags
                        and "spider-max" not in e.tags
                    ):
                        found_url_unverified_dummy = True
            if e.type == "URL" and e.data == "http://127.0.0.1:8888/spider":
                found_url_event = True

        assert found_url_unverified_spider_max, "Excavate failed to find /spider link"
        assert found_url_unverified_dummy, "Dummy module did not correctly re-emit"
        assert found_url_event, "URL was not emitted from non-spider-max URL_UNVERIFIED"


class TestExcavateParameterExtraction_targeturl(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/?foo=1"]
    modules_overrides = ["httpx", "excavate", "hunt"]
    config_overrides = {
        "url_querystring_remove": False,
        "url_querystring_collapse": False,
        "interactsh_disable": True,
        "modules": {
            "excavate": {
                "retain_querystring": True,
            }
        },
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
    targets = ["http://127.0.0.1:8888/?foo=1"]
    modules_overrides = ["httpx", "excavate", "hunt"]
    config_overrides = {
        "url_querystring_remove": False,
        "url_querystring_collapse": False,
        "interactsh_disable": True,
        "web_spider_depth": 4,
        "web_spider_distance": 4,
        "modules": {
            "excavate": {
                "retain_querystring": True,
            }
        },
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
        "url_querystring_remove": False,
        "url_querystring_collapse": False,
        "interactsh_disable": True,
        "web_spider_depth": 4,
        "web_spider_distance": 4,
        "modules": {
            "excavate": {
                "retain_querystring": True,
            }
        },
    }

    def check(self, module_test, events):
        web_parameter_emit = False
        for e in events:
            if e.type == "WEB_PARAMETER" and "foo" not in e.data["url"]:
                web_parameter_emit = True

        assert web_parameter_emit


class TestExcavate_webparameter_outofscope(ModuleTestBase):
    html_body = "<html><a class=button href='https://socialmediasite.com/send?text=foo'><a class=button href='https://outofscope.com/send?text=foo'></html>"

    targets = ["http://127.0.0.1:8888", "socialmediasite.com"]
    modules_overrides = ["httpx", "excavate", "hunt"]
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


class TestExcavateHeaders(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["excavate", "httpx", "hunt"]
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
    targets = ["http://127.0.0.1:8888/", "test.notreal"]
    modules_overrides = ["excavate", "httpx", "filedownload", "extractous"]
    config_overrides = {"scope": {"report_distance": 1}, "web": {"spider_distance": 2, "spider_depth": 2}}

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
    extractous_response = """This is an email example@blacklanternsecurity.notreal

An example JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

A serialized DOTNET object AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5TdHJpbmddXSwgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49YjAzZjVmN2YxMWQ1MGFlMwEAAAAIQ29tcGFyZXIQSXRlbUNvdW50AQMAAAAJAwAAAAlTeXN0ZW0uU3RyaW5nW10FAAAACQIAAAAJBAAAAAkFAAAACRcAAAAJCgAAAAkLAAAACQwAAAAJDQAAAAkOAAAACQ8AAAAJEAAAAAkRAAAACRIAAAAJEwAAAA==

A full url https://www.test.notreal/about

A href <a href='/donot_detect.js'>Click me</a>"""

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
        assert raw_text_events[0].data == self.extractous_response, (
            f"Text extracted from PDF is incorrect, got {raw_text_events[0].data}"
        )
        email_events = [e for e in events if e.type == "EMAIL_ADDRESS"]
        assert 1 == len(email_events), "Failed to emit EMAIL_ADDRESS event"
        assert email_events[0].data == "example@blacklanternsecurity.notreal", (
            f"Email extracted from extractous text is incorrect, got {email_events[0].data}"
        )
        finding_events = [e for e in events if e.type == "FINDING"]
        assert 2 == len(finding_events), "Failed to emit FINDING events"
        assert any(
            e.type == "FINDING"
            and "JWT" in e.data["description"]
            and e.data["url"] == "http://127.0.0.1:8888/Test_PDF"
            and e.data["host"] == "127.0.0.1"
            and e.data["path"].endswith("http-127-0-0-1-8888-test-pdf.pdf")
            and str(e.host) == "127.0.0.1"
            for e in finding_events
        ), f"Failed to emit JWT event got {finding_events}"
        assert any(
            e.type == "FINDING"
            and "DOTNET" in e.data["description"]
            and e.data["url"] == "http://127.0.0.1:8888/Test_PDF"
            and e.data["host"] == "127.0.0.1"
            and e.data["path"].endswith("http-127-0-0-1-8888-test-pdf.pdf")
            and str(e.host) == "127.0.0.1"
            for e in finding_events
        ), f"Failed to emit serialized event got {finding_events}"
        assert finding_events[0].data["path"] == str(file), "File path not included in finding event"
        url_events = [e.data for e in events if e.type == "URL_UNVERIFIED"]
        assert "https://www.test.notreal/about" in url_events, (
            f"URL extracted from extractous text is incorrect, got {url_events}"
        )
        assert "/donot_detect.js" not in url_events, (
            f"URL extracted from extractous text is incorrect, got {url_events}"
        )


class TestExcavateBadURLs(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["excavate", "httpx", "hunt"]
    config_overrides = {"interactsh_disable": True, "scope": {"report_distance": 10}}

    bad_url_data = """
<a href='mailto:bob@evilcorp.org?subject=help'>Help</a>
<a href='https://ssl.'>Help</a>
"""

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests({"uri": "/"}, {"response_data": self.bad_url_data})

    def check(self, module_test, events):
        debug_log_content = read_gzipped_file(module_test.scan.home / "debug.log.gz")
        # make sure our logging is working
        assert "Setting scan status to STARTING" in debug_log_content
        # make sure we don't have any URL validation errors
        assert "Error Parsing reconstructed URL" not in debug_log_content
        assert "Error sanitizing event data" not in debug_log_content

        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        assert sorted([e.data for e in url_events]) == sorted(["https://ssl/", "http://127.0.0.1:8888/"])
