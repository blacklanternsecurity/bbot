from .test_module_paramminer_headers import Paramminer_Headers, tempwordlist, helper


class TestParamminer_Getparams(Paramminer_Headers):
    modules_overrides = ["httpx", "paramminer_getparams"]
    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist(["canary", "id"])}}}

    getparam_body = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello null!</p>';
    </body>
    </html>
    """

    getparam_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello AAAAAAAAAAAAAA!</p>';
    </body>
    </html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"query_string": b"id=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[Paramminer] Getparam: [id] Reasons: [body] Reflection: [True]" in e.data["description"]
            for e in events
        )
        assert not any(
            e.type == "FINDING" and "[Paramminer] Getparam: [canary] Reasons: [body]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_noreflection(TestParamminer_Getparams):
    getparam_body_match = """
    <html>
    <title>the title</title>
    <body>
    <p>Hello ADMINISTRATOR!</p>';
    </body>
    </html>
    """

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[Paramminer] Getparam: [id] Reasons: [body] Reflection: [False]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_singlewordlist(TestParamminer_Getparams):
    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist(["id"])}}}


class TestParamminer_Getparams_boring_off(TestParamminer_Getparams):
    config_overrides = {
        "modules": {
            "paramminer_getparams": {"skip_boring_words": False, "wordlist": tempwordlist(["canary", "boring"])}
        }
    }

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.scan.modules["paramminer_getparams"].boring_words = {"boring"}
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"query_string": b"boring=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and "[Paramminer] Getparam: [boring] Reasons: [body]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_boring_on(TestParamminer_Getparams_boring_off):
    config_overrides = {
        "modules": {
            "paramminer_getparams": {"skip_boring_words": True, "wordlist": tempwordlist(["canary", "boring"])}
        }
    }

    def check(self, module_test, events):
        assert not any(
            e.type == "FINDING" and "[Paramminer] Getparam: [boring] Reasons: [body]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_Extract_Json(Paramminer_Headers):
    modules_overrides = ["httpx", "paramminer_getparams"]
    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist([]), "http_extract": True}}}

    getparam_extract_json = """
    {
  "obscureParameter": 1,
  "common": 1
}
    """

    getparam_extract_json_match = """
    {
  "obscureParameter": "AAAAAAAAAAAAAA",
  "common": 1
}
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )

        expect_args = {"query_string": b"obscureParameter=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {
            "response_data": self.getparam_extract_json_match,
            "headers": {"Content-Type": "application/json"},
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_extract_json, "headers": {"Content-Type": "application/json"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[Paramminer] Getparam: [obscureParameter] Reasons: [body]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_Extract_Xml(Paramminer_Headers):
    modules_overrides = ["httpx", "paramminer_getparams"]
    config_overrides = {
        "modules": {
            "paramminer_getparams": {"wordlist": tempwordlist([]), "http_extract": True, "skip_boring_words": True}
        }
    }

    getparam_extract_xml = """
<data>
    <obscureParameter>1</obscureParameter>
    <common>1</common>
</data>
    """

    getparam_extract_xml_match = """
<data>
    <obscureParameter>AAAAAAAAAAAAAA</obscureParameter>
    <common>1</common>
</data>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        module_test.scan.modules["paramminer_getparams"].boring_words = {"data", "common"}

        expect_args = {"query_string": b"obscureParameter=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {
            "response_data": self.getparam_extract_xml_match,
            "headers": {"Content-Type": "application/xml"},
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_extract_xml, "headers": {"Content-Type": "application/xml"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING"
            and "[Paramminer] Getparam: [obscureParameter] Reasons: [body]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_Extract_Html(Paramminer_Headers):
    modules_overrides = ["httpx", "paramminer_getparams"]
    config_overrides = {
        "modules": {"paramminer_getparams": {"wordlist": tempwordlist(["canary"]), "http_extract": True}}
    }

    getparam_extract_html = """
<html><a href="/?hack=1">ping</a></html>
    """

    getparam_extract_html_match = """
<html><a href="/?hack=1">ping</a><p>HackThePlanet</p></html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )

        expect_args = {"query_string": b"id=AAAAAAAAAAAAAA&hack=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_extract_html_match, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"query_string": b"hack=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_extract_html_match, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_extract_html, "headers": {"Content-Type": "text/html"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and "[Paramminer] Getparam: [hack] Reasons: [body]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_finish(Paramminer_Headers):
    modules_overrides = ["httpx", "excavate", "paramminer_getparams"]
    config_overrides = {
        "modules": {"paramminer_getparams": {"wordlist": tempwordlist(["canary", "canary2"]), "http_extract": True}}
    }

    targets = ["http://127.0.0.1:8888/test1.php", "http://127.0.0.1:8888/test2.php"]

    test_1_html = """
<html><a href="/test2.php?abcd1234=foo">paramstest2</a></html>
    """

    test_2_html = """
<html></a><p>Hello</p></html>
    """

    test_2_html_match = """
<html></a><p>HackThePlanet!</p></html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )

        expect_args = {"uri": "/test2.php", "query_string": b"abcd1234=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.test_2_html_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"uri": "/test2.php"}
        respond_args = {"response_data": self.test_2_html}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"uri": "/test1.php"}
        respond_args = {"response_data": self.test_1_html}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(
            e.type == "FINDING" and "[abcd1234] Reasons: [body] Reflection: [False]" in e.data["description"]
            for e in events
        )
