from .base import ModuleTestBase


class TestUrl_Manipulation(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "url_manipulation"]
    body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """

    async def setup_after_prep(self, module_test):
        expect_args = {"query_string": f"{module_test.module.rand_string}=.xml".encode()}
        respond_args = {"response_data": self.body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and e.data["description"]
            == f"Url Manipulation: [body] Sig: [Modified URL: http://127.0.0.1:8888/?{module_test.module.rand_string}=.xml]"
            for e in events
        )
