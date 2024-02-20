from .base import ModuleTestBase


class TestHTTPX(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/url", "127.0.0.1:8888"]
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
    config_overrides = {"internal_modules": {"speculate": {"ports": "8888,9999"}}}

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
