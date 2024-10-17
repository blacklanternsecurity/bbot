from .base import ModuleTestBase


class TestHTTPXBase(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/url", "127.0.0.1:8888"]
    module_name = "httpx"
    modules_overrides = ["httpx", "excavate"]
    config_overrides = {"modules": {"httpx": {"store_responses": True}}}

    # HTML for a page with a login form
    html_with_login = """
<html>
<body>
    <form>
        <input type="text" name="username">
        <input name="password">
        <input type="submit" value="Login">
    </form>
</body>
</html>"""

    # HTML for a page without a login form
    html_without_login = """
<html>
<body>
    <form>
        <input type="text" name="search">
        <input type="submit" value="Search">
    </form>
</body>
</html>"""

    async def setup_after_prep(self, module_test):
        request_args = dict(uri="/", headers={"test": "header"})
        respond_args = dict(response_data=self.html_without_login)
        module_test.set_expect_requests(request_args, respond_args)
        request_args = dict(uri="/url", headers={"test": "header"})
        respond_args = dict(response_data=self.html_with_login)
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        url = False
        open_port = False
        for e in events:
            if e.type == "HTTP_RESPONSE":
                if e.data["path"] == "/":
                    assert not "login-page" in e.tags
                    open_port = True
                elif e.data["path"] == "/url":
                    assert "login-page" in e.tags
                    url = True
        assert url, "Failed to visit target URL"
        assert open_port, "Failed to visit target OPEN_TCP_PORT"
        saved_response = module_test.scan.home / "httpx" / "127.0.0.1.8888[slash]url.txt"
        assert saved_response.is_file(), "Failed to save raw httpx response"


class TestHTTPX_404(ModuleTestBase):
    targets = ["https://127.0.0.1:9999"]
    modules_overrides = ["httpx", "speculate", "excavate"]
    config_overrides = {"modules": {"speculate": {"ports": "8888,9999"}}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "Redirecting...", status=301, headers={"Location": "https://127.0.0.1:9999"}
        )
        module_test.httpserver_ssl.expect_request("/").respond_with_data("404 not found", status=404)

    def check(self, module_test, events):
        assert 1 == len(
            [e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and "status-301" in e.tags]
        )
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "https://127.0.0.1:9999/"])


class TestHTTPX_Redirect(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "speculate", "excavate"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            "Redirecting...", status=301, headers={"Location": "http://www.evilcorp.com"}
        )

    def check(self, module_test, events):
        assert 1 == len(
            [e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/" and "status-301" in e.tags]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "URL_UNVERIFIED" and e.data == "http://www.evilcorp.com/" and "affiliate" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in events
                if e.type.startswith("DNS_NAME") and e.data == "www.evilcorp.com" and "affiliate" in e.tags
            ]
        )


class TestHTTPX_URLBlacklist(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "speculate", "excavate"]
    config_overrides = {"web": {"spider_distance": 10, "spider_depth": 10}}

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data(
            """
            <a href="/test.aspx"/>
            <a href="/test.svg"/>
            <a href="/test.woff2"/>
            <a href="/test.txt"/>
            """
        )

    def check(self, module_test, events):
        assert 4 == len([e for e in events if e.type == "URL_UNVERIFIED"])
        assert 3 == len([e for e in events if e.type == "HTTP_RESPONSE"])
        assert 3 == len([e for e in events if e.type == "URL"])
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/"])
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/test.aspx"])
        assert 1 == len([e for e in events if e.type == "URL" and e.data == "http://127.0.0.1:8888/test.txt"])
        assert not any([e for e in events if "URL" in e.type and ".svg" in e.data])
        assert not any([e for e in events if "URL" in e.type and ".woff" in e.data])


class TestHTTPX_querystring_removed(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "speculate", "excavate"]

    async def setup_after_prep(self, module_test):
        module_test.httpserver.expect_request("/").respond_with_data('<a href="/test.php?foo=bar"/>')

    def check(self, module_test, events):
        assert [e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/test.php"]


class TestHTTPX_querystring_notremoved(TestHTTPX_querystring_removed):
    config_overrides = {"url_querystring_remove": False}

    def check(self, module_test, events):
        assert [e for e in events if e.type == "URL_UNVERIFIED" and e.data == "http://127.0.0.1:8888/test.php?foo=bar"]
