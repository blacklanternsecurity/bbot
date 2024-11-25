from .test_module_paramminer_headers import Paramminer_Headers, tempwordlist, helper


class TestParamminer_Cookies(Paramminer_Headers):
    modules_overrides = ["httpx", "paramminer_cookies"]
    config_overrides = {"modules": {"paramminer_cookies": {"wordlist": tempwordlist(["junkcookie", "admincookie"])}}}

    cookies_body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    cookies_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_cookies"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"headers": {"Cookie": "admincookie=AAAAAAAAAAAAAA"}}
        respond_args = {"response_data": self.cookies_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.cookies_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        found_reflected_cookie = False
        false_positive_match = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "[Paramminer] Cookie: [admincookie] Reasons: [body] Reflection: [True]" in e.data["description"]:
                    found_reflected_cookie = True

                if "junkcookie" in e.data["description"]:
                    false_positive_match = True

        assert found_reflected_cookie, "Failed to find hidden reflected cookie parameter"
        assert not false_positive_match, "Found word which was in wordlist but not a real match"


class TestParamminer_Cookies_noreflection(TestParamminer_Cookies):
    cookies_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello ADMINISTRATOR!</p>';
    </body>
    </html>
    """

    def check(self, module_test, events):
        assert any(
            e.type == "WEB_PARAMETER"
            and "[Paramminer] Cookie: [admincookie] Reasons: [body] Reflection: [False]" in e.data["description"]
            for e in events
        )
