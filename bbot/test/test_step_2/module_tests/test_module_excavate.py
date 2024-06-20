from .base import ModuleTestBase


class TestExcavate(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/", "test.notreal", "http://127.0.0.1:8888/subdir/links.html"]
    modules_overrides = ["excavate", "httpx"]
    config_overrides = {"web_spider_distance": 1, "web_spider_depth": 1}

    async def setup_before_prep(self, module_test):
        response_data = """
        ftp://ftp.test.notreal
        \\nhttps://www1.test.notreal
        \\x3dhttps://www2.test.notreal
        %0ahttps://www3.test.notreal
        \\u000ahttps://www4.test.notreal
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
        assert not "http://127.0.0.1:8888/a_relative.js" in event_data
        assert not "http://127.0.0.1:8888/link_relative.js" in event_data
        assert "http://127.0.0.1:8888/a_relative.txt" in event_data
        assert "http://127.0.0.1:8888/link_relative.txt" in event_data

        assert "nhttps://www1.test.notreal/" not in event_data
        assert "x3dhttps://www2.test.notreal/" not in event_data
        assert "a2https://www3.test.notreal/" not in event_data
        assert "uac20https://www4.test.notreal/" not in event_data
        assert "nwww5.test.notreal" not in event_data
        assert "x3dwww6.test.notreal" not in event_data
        assert "a2www7.test.notreal" not in event_data
        assert "uac20www8.test.notreal" not in event_data

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
            and "spider-danger" not in e.tags
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED"
            and e.data == "http://127.0.0.1:8888/2/depth2.html"
            and "spider-danger" in e.tags
            for e in events
        )

        assert any(
            e.type == "URL_UNVERIFIED"
            and e.data == "http://127.0.0.1:8888/distance2.html"
            and "spider-danger" in e.tags
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
    config_overrides = {"scope_report_distance": 1}

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
        assert 2 == len(
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
            [e for e in events if e.type == "PROTOCOL" and e.data["protocol"] == "SMB" and not "port" in e.data]
        )
        assert 0 == len([e for e in events if e.type == "FINDING" and "ssh://127.0.0.1" in e.data["description"]])
        assert 0 == len([e for e in events if e.type == "PROTOCOL" and e.data["protocol"] == "SSH"])


class TestExcavateMaxLinksPerPage(TestExcavate):
    targets = ["http://127.0.0.1:8888/"]
    config_overrides = {"web_spider_links_per_page": 10, "web_spider_distance": 1}

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
        # base URL + 25 links (10 w/o spider-danger) + 10 links (extracted from HTTP_RESPONSES, w/ spider-danger) == 36
        assert len(url_unverified_events) == 36
        url_data = [e.data for e in url_unverified_events if "spider-danger" not in e.tags]
        assert len(url_data) == 11
        assert "http://127.0.0.1:8888/10" in url_data
        assert "http://127.0.0.1:8888/11" not in url_data
        url_events = [e for e in events if e.type == "URL"]
        assert len(url_events) == 11


class TestExcavateCSP(TestExcavate):
    csp_test_header = "default-src 'self'; script-src test.asdf.fakedomain; object-src 'none';"

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"headers": {"Content-Security-Policy": self.csp_test_header}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.data == "test.asdf.fakedomain" for e in events)


class TestExcavateURL(TestExcavate):
    async def setup_before_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "SomeSMooshedDATAhttps://asdffoo.test.notreal/some/path"
        )

    def check(self, module_test, events):
        assert any(e.data == "asdffoo.test.notreal" for e in events)
        assert any(e.data == "https://asdffoo.test.notreal/some/path" for e in events)


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
        for serialize_type in ["Java", ".NET", "PHP (Array)", "PHP (String)", "PHP (Object)", "Possible Compressed"]:
            assert any(
                e.type == "FINDING" and serialize_type in e.data["description"] for e in events
            ), f"Did not find {serialize_type} Serialized Object"


class TestExcavateRawData(TestExcavate):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["unstructured", "filedownload", "httpx", "excavate"]
    config_overrides = {"web_spider_distance": 2, "web_spider_depth": 2}

    pdf_data = """%PDF-1.3
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
/Author (anonymous) /CreationDate (D:20240605141216+00'00') /Creator (ReportLab PDF Library - www.reportlab.com) /Keywords () /ModDate (D:20240605141216+00'00') /Producer (ReportLab PDF Library - www.reportlab.com) 
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
/Filter [ /ASCII85Decode /FlateDecode ] /Length 132
>>
stream
GapQh0E=F,0U\H3T\pNYT^QKk?tc>IP,;W#U1^23ihPEM_?CW4KISi90MjG^2,FS#<RAf8.4MLLf/GNAf/!Cn6RrNecqhb7/kO8[:,UJC.*9`]<!^TD#gi^AU;-p49&LT2~>endstream
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
[<4ec66ff265d6f71192a8280f8a3a00ac><4ec66ff265d6f71192a8280f8a3a00ac>]
% ReportLab generated PDF document -- digest (http://www.reportlab.com)

/Info 5 0 R
/Root 4 0 R
/Size 8
>>
startxref
1059
%%EOF"""

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            dict(uri="/"),
            dict(response_data='<a href="/Test_PDF"/>'),
        )
        module_test.set_expect_requests(
            dict(uri="/Test_PDF"),
            dict(response_data=self.pdf_data, headers={"Content-Type": "application/pdf"}),
        )

    def check(self, module_test, events):
        assert any(
            e.type == "URL_UNVERIFIED"
            and e.data == "http://127.0.0.1:8888/distance2.html"
            and "spider-danger" in e.tags
            for e in events
        )
