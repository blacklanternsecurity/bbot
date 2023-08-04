from .base import ModuleTestBase


class TestHTTPX(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/url", "127.0.0.1:8888"]

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
