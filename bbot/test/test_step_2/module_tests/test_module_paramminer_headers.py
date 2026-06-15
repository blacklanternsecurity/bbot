from bbot.core.helpers import helper

from .base import ModuleTestBase, tempwordlist


class Paramminer_Headers(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "paramminer_headers"]
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
    modules_overrides = ["http", "paramminer_headers", "excavate"]
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
    modules_overrides = ["http", "excavate"]
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


class TestParamminerHeadersWildcardSkip(ModuleTestBase):
    """When the host is an HTTP wildcard, paramminer_headers should skip fuzzing entirely."""

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "paramminer_headers"]
    config_overrides = {"modules": {"paramminer_headers": {"wordlist": tempwordlist(["tracestate"])}}}

    async def setup_before_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={"response_data": "<html><body>hello</body></html>"},
        )

    async def setup_after_prep(self, module_test):
        async def mock_wildcard(scheme, host, port):
            return True

        module_test.scan.helpers.web.is_http_wildcard_host = mock_wildcard

    def check(self, module_test, events):
        web_params = [e for e in events if e.type == "WEB_PARAMETER" and str(e.module) == "paramminer_headers"]
        assert len(web_params) == 0, f"paramminer_headers should not fuzz wildcard hosts, but emitted: {web_params}"


class TestParamminerHeadersDedupValueMutations(Paramminer_Headers):
    """Value mutations of the same parameter set on the same endpoint should collapse to one test surface."""

    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)
        pm = module_test.scan.modules["paramminer_headers"]

        def make_wp(**kwargs):
            defaults = {"host": "127.0.0.1:8888", "type": "GETPARAM", "original_value": "x"}
            defaults.update(kwargs)
            return module_test.scan.make_event(defaults, "WEB_PARAMETER", dummy=True)

        def make_hr(url):
            return module_test.scan.make_event(
                {
                    "url": url,
                    "status_code": 200,
                    "header-dict": {},
                    "body": "",
                    "raw_header": "HTTP/1.1 200 OK\r\n\r\n",
                    "method": "GET",
                },
                "HTTP_RESPONSE",
                dummy=True,
            )

        # same endpoint, same param keys, different values (simulates lightfuzz probe cycling)
        hash_a, _ = pm._incoming_dedup_hash(
            make_wp(
                url="http://127.0.0.1:8888/page?culture=probe_a&page=1",
                name="culture",
                additional_params={"page": "1"},
            )
        )
        hash_b, _ = pm._incoming_dedup_hash(
            make_wp(
                url="http://127.0.0.1:8888/page?culture=probe_b&page=2",
                name="culture",
                additional_params={"page": "2"},
            )
        )
        assert hash_a == hash_b, "Value mutations of same param keys should produce same dedup hash"

        # different param keys on same path -> distinct
        hash_c, _ = pm._incoming_dedup_hash(
            make_wp(
                url="http://127.0.0.1:8888/page?culture=x&page=1&csrf=tok",
                name="culture",
                additional_params={"page": "1", "csrf": "tok"},
            )
        )
        assert hash_a != hash_c, "Different param key sets should produce different dedup hashes"

        # different path, same keys -> distinct
        hash_d, _ = pm._incoming_dedup_hash(
            make_wp(
                url="http://127.0.0.1:8888/other?culture=x&page=1",
                name="culture",
                additional_params={"page": "1"},
            )
        )
        assert hash_a != hash_d, "Same param keys on different paths should produce different dedup hashes"

        # different focus name, same sibling keys (excavate emits one WP per param) -> distinct
        hash_e, _ = pm._incoming_dedup_hash(
            make_wp(
                url="http://127.0.0.1:8888/page?culture=x&page=1",
                name="page",
                additional_params={"culture": "x"},
            )
        )
        assert hash_a != hash_e, "Different focus name with same siblings should produce different dedup hashes"

        # HTTP_RESPONSE events: same endpoint collapses regardless
        hash_hr_a, _ = pm._incoming_dedup_hash(make_hr("http://127.0.0.1:8888/page"))
        hash_hr_b, _ = pm._incoming_dedup_hash(make_hr("http://127.0.0.1:8888/page"))
        assert hash_hr_a == hash_hr_b, "HTTP_RESPONSE events for same endpoint should produce same dedup hash"

        # WEB_PARAMETER and HTTP_RESPONSE for same URL should NOT collide
        assert hash_a != hash_hr_a, "WEB_PARAMETER and HTTP_RESPONSE should not share dedup hashes"

    def check(self, module_test, events):
        super().check(module_test, events)
