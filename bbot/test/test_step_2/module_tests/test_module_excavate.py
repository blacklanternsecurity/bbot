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
        <a src="http://www9.test.notreal">
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
        assert "http://www9.test.notreal/" in event_data

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
        url_events = [e for e in events if e.type == "URL_UNVERIFIED"]
        assert len(url_events) == 26
        url_data = [e.data for e in url_events if "spider-danger" not in e.tags]
        assert "http://127.0.0.1:8888/10" in url_data
        assert "http://127.0.0.1:8888/11" not in url_data


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
