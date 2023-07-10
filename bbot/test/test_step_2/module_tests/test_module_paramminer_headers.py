from bbot.core.helpers import helper

from .base import ModuleTestBase, tempwordlist


class TestParamminer_Headers(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "paramminer_headers"]
    config_overrides = {"modules": {"paramminer_headers": {"wordlist": tempwordlist(["junkword1", "tracestate"])}}}

    headers_body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    headers_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_headers"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = dict(headers={"tracestate": "AAAAAAAAAAAAAA"})
        respond_args = {"response_data": self.headers_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.headers_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[Paramminer] Header: [tracestate] Reasons: [body] Reflection: [True]" in e.data["description"]
            for e in events
        )
        assert not any(
            e.type == "FINDING" and "[Paramminer] Header: [junkword1]" in e.data["description"] for e in events
        )


class TestParamminer_Headers(TestParamminer_Headers):
    headers_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello Administrator!</p>';
    </body>
    </html>
    """

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[Paramminer] Header: [tracestate] Reasons: [body] Reflection: [False]" in e.data["description"]
            for e in events
        )
