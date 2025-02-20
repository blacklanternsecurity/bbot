from bbot.core.helpers import helper

from .base import ModuleTestBase, tempwordlist


class Paramminer_Headers(ModuleTestBase):
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
        module_test.scan.modules["paramminer_headers"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"headers": {"tracestate": "AAAAAAAAAAAAAA"}}
        respond_args = {"response_data": self.headers_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.headers_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        found_reflected_header = False
        false_positive_match = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "[Paramminer] Header: [tracestate] Reasons: [body] Reflection: [True]" in e.data["description"]:
                    found_reflected_header = True

                if "junkword1" in e.data["description"]:
                    false_positive_match = True

        assert found_reflected_header, "Failed to find hidden reflected header parameter"
        assert not false_positive_match, "Found word which was in wordlist but not a real match"


class TestParamminer_Headers(Paramminer_Headers):
    pass


class TestParamminer_Headers_noreflection(Paramminer_Headers):
    found_nonreflected_header = False

    headers_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello Administrator!</p>';
    </body>
    </html>
    """

    def check(self, module_test, events):
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "[Paramminer] Header: [tracestate] Reasons: [body] Reflection: [False]" in e.data["description"]:
                    found_nonreflected_header = True

        assert found_nonreflected_header, "Failed to find hidden non-reflected header parameter"


class TestParamminer_Headers_extract(Paramminer_Headers):
    modules_overrides = ["httpx", "paramminer_headers", "excavate"]
    config_overrides = {
        "modules": {
            "paramminer_headers": {"wordlist": tempwordlist(["junkword1", "tracestate"]), "recycle_words": True}
        }
    }

    headers_body = """
    <html>
    <title>the title</title>
    <body>
    <a href="/page?foo=AAAAAAAAAAAAAA">Click Me</a>
    </body>
    </html>
    """

    headers_body_match = """
    <html>
    <title>the title</title>
    <body>
    <a href="/page?foo=AAAAAAAAAAAAAA">Click Me</a>
    <a href="/page?foo=http://thisisjunk.com?whatever=value">Click Me</a>
    <p>Secret param "foo" found with value: AAAAAAAAAAAAAA</p>
    </body>
    </html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_headers"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"headers": {"foo": "AAAAAAAAAAAAAA"}}
        respond_args = {"response_data": self.headers_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.headers_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_extracted_web_parameter = False
        used_recycled_parameter = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [foo] (HTML Tags Submodule)" in e.data["description"]:
                    excavate_extracted_web_parameter = True
                if "[Paramminer] Header: [foo] Reasons: [body] Reflection: [True]" in e.data["description"]:
                    used_recycled_parameter = True

        assert excavate_extracted_web_parameter, "Excavate failed to extract WEB_PARAMETER"
        assert used_recycled_parameter, "Failed to find header with recycled parameter"


class TestParamminer_Headers_extract_norecycle(TestParamminer_Headers_extract):
    modules_overrides = ["httpx", "excavate"]
    config_overrides = {}

    async def setup_after_prep(self, module_test):
        respond_args = {"response_data": self.headers_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_extracted_web_parameter = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "HTTP Extracted Parameter [foo] (HTML Tags Submodule)" in e.data["description"]:
                    excavate_extracted_web_parameter = True

        assert not excavate_extracted_web_parameter, (
            "Excavate extract WEB_PARAMETER despite disabling parameter extraction"
        )


class TestParamminer_Headers_NoCookieRetention(Paramminer_Headers):
    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_headers"].helpers.rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )

        expect_args = {"headers": {"tracestate": "AAAAAAAAAAAAAA"}}
        respond_args = {"response_data": self.headers_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        headers_body_with_cookie = """
        <html>
        <title>the title</title>
        <body>
        <p>Hello with cookie!</p>';
        </body>
        </html>
        """
        expect_args = {"headers": {"Cookie": "test_cookie=cookie_value; AAAAAAAAAAAAAA=AAAAAAAAAAAAAA"}}
        respond_args_with_cookie_body_change = {"response_data": headers_body_with_cookie}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args_with_cookie_body_change)

        respond_args_default = {
            "response_data": self.headers_body,
            "headers": {"set-cookie": "test_cookie=cookie_value"},
        }
        module_test.set_expect_requests(respond_args=respond_args_default)

    def check(self, module_test, events):
        found_web_parameter = False
        found_web_parameter_false_positive = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "[Paramminer] Header: [tracestate]" in e.data["description"]:
                    found_web_parameter = True
                if "junkword1" in e.data["description"]:
                    found_web_parameter_false_positive = True

        assert found_web_parameter, "WEB_PARAMETER event was not emitted"
        assert not found_web_parameter_false_positive, "WEB_PARAMETER event was emitted with false positive"
