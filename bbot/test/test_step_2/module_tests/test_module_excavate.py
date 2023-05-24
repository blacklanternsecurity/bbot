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
    targets = ["http://127.0.0.1:8888/", "http://127.0.0.1:8888/relative/"]
    config_overrides = {"scope_report_distance": 1}

    async def setup_before_prep(self, module_test):
        # absolute redirect
        module_test.httpserver.expect_request("/").respond_with_data(
            "", status=302, headers={"Location": "https://www.test.notreal/yep"}
        )
        module_test.httpserver.expect_request("/relative/").respond_with_data(
            "", status=302, headers={"Location": "./owa/"}
        )
        module_test.httpserver.no_handler_status_code = 404

    def check(self, module_test, events):
        assert any(e.data == "https://www.test.notreal/yep" for e in events)
        assert any(e.data == "http://127.0.0.1:8888/relative/owa/" for e in events)
