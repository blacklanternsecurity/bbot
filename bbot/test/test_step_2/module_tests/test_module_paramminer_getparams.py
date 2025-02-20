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
            e.type == "WEB_PARAMETER"
            and "[Paramminer] Getparam: [id] Reasons: [body] Reflection: [True]" in e.data["description"]
            for e in events
        )
        assert not any(
            e.type == "WEB_PARAMETER" and "[Paramminer] Getparam: [canary] Reasons: [body]" in e.data["description"]
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
            e.type == "WEB_PARAMETER"
            and "[Paramminer] Getparam: [id] Reasons: [body] Reflection: [False]" in e.data["description"]
            for e in events
        )


class TestParamminer_Getparams_singlewordlist(TestParamminer_Getparams):
    config_overrides = {"modules": {"paramminer_getparams": {"wordlist": tempwordlist(["id"])}}}


class TestParamminer_Getparams_boring_off(TestParamminer_Getparams):
    config_overrides = {
        "modules": {
            "paramminer_getparams": {"skip_boring_words": False, "wordlist": tempwordlist(["canary", "utm_term"])}
        }
    }

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"query_string": b"utm_term=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_body_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_body}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        emitted_boring_parameter = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if "utm_term" in e.data["description"]:
                    emitted_boring_parameter = True
        assert emitted_boring_parameter, "failed to emit boring parameter with skip_boring_words disabled"


class TestParamminer_Getparams_boring_on(TestParamminer_Getparams_boring_off):
    config_overrides = {
        "modules": {
            "paramminer_getparams": {"skip_boring_words": True, "wordlist": tempwordlist(["canary", "boring"])}
        }
    }

    def check(self, module_test, events):
        emitted_boring_parameter = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if "boring" in e.data["description"]:
                    emitted_boring_parameter = True

        assert not emitted_boring_parameter, "emitted boring parameter with skip_boring_words enabled"


class TestParamminer_Getparams_finish(Paramminer_Headers):
    modules_overrides = ["httpx", "excavate", "paramminer_getparams"]
    config_overrides = {
        "modules": {"paramminer_getparams": {"wordlist": tempwordlist(["canary", "canary2"]), "recycle_words": True}}
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

        expect_args = {"uri": "/test1.php", "query_string": b"abcd1234=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.test_2_html_match}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"uri": "/test1.php"}
        respond_args = {"response_data": self.test_1_html}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        excavate_extracted_web_parameter = False
        found_hidden_getparam_recycled = False
        emitted_excavate_paramminer_duplicate = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "http://127.0.0.1:8888/test2.php" in e.data["url"]
                    and "HTTP Extracted Parameter [abcd1234] (HTML Tags Submodule)" in e.data["description"]
                ):
                    excavate_extracted_web_parameter = True

                if (
                    "http://127.0.0.1:8888/test1.php" in e.data["url"]
                    and "[Paramminer] Getparam: [abcd1234] Reasons: [body] Reflection: [False]"
                    in e.data["description"]
                ):
                    found_hidden_getparam_recycled = True

                if (
                    "http://127.0.0.1:8888/test2.php" in e.data["url"]
                    and "[Paramminer] Getparam: [abcd1234] Reasons: [body] Reflection: [False]"
                    in e.data["description"]
                ):
                    emitted_excavate_paramminer_duplicate = True

        assert excavate_extracted_web_parameter, "Excavate failed to extract GET parameter"
        assert found_hidden_getparam_recycled, "Failed to find hidden GET parameter"
        # the fact that it is a duplicate is OK, because it still won't be consumed mutltiple times. But we do want to make sure both modules try to emit it
        assert emitted_excavate_paramminer_duplicate, "Paramminer emitted duplicate already found by excavate"


class TestParamminer_Getparams_xmlspeculative(Paramminer_Headers):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["httpx", "excavate", "paramminer_getparams"]
    config_overrides = {
        "modules": {
            "excavate": {"speculate_params": True},
            "paramminer_getparams": {"wordlist": tempwordlist(["data", "common"]), "recycle_words": False},
        }
    }
    getparam_extract_xml = """
    <data>
     <junkparameter>1</junkparameter>
     <obscureParameter>1</obscureParameter>
         <common>1</common>
     </data>
    """

    getparam_speculative_used = """
    <html>
    <p>secret parameter used</p>
    </html>
    """

    async def setup_after_prep(self, module_test):
        module_test.scan.modules["paramminer_getparams"].rand_string = lambda *args, **kwargs: "AAAAAAAAAAAAAA"
        module_test.monkeypatch.setattr(
            helper.HttpCompare, "gen_cache_buster", lambda *args, **kwargs: {"AAAAAA": "1"}
        )
        expect_args = {"query_string": b"obscureParameter=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_speculative_used}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"query_string": b"data=AAAAAAAAAAAAAA&obscureParameter=AAAAAAAAAAAAAA&AAAAAA=1"}
        respond_args = {"response_data": self.getparam_speculative_used}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        respond_args = {"response_data": self.getparam_extract_xml, "headers": {"Content-Type": "application/xml"}}
        module_test.set_expect_requests(respond_args=respond_args)

    def check(self, module_test, events):
        excavate_discovered_speculative = False
        paramminer_used_speculative = False
        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "HTTP Extracted Parameter (speculative from xml content) [obscureParameter]"
                    in e.data["description"]
                ):
                    excavate_discovered_speculative = True

                if (
                    "[Paramminer] Getparam: [obscureParameter] Reasons: [header,body] Reflection: [False]"
                    in e.data["description"]
                ):
                    paramminer_used_speculative = True

        assert excavate_discovered_speculative, "Excavate failed to discover speculative xml parameter"
        assert paramminer_used_speculative, "Paramminer failed to confirm speculative GET parameter"


class TestParamminer_Getparams_filter_static(TestParamminer_Getparams_finish):
    targets = ["http://127.0.0.1:8888/test1.php", "http://127.0.0.1:8888/test2.pdf"]

    test_1_html = """
    <html><a href="/test2.pdf?abcd1234=foo">paramstest2</a></html>
    """

    def check(self, module_test, events):
        found_hidden_getparam_recycled = False
        emitted_excavate_paramminer_duplicate = False

        for e in events:
            if e.type == "WEB_PARAMETER":
                if (
                    "http://127.0.0.1:8888/test1.php" in e.data["url"]
                    and "[Paramminer] Getparam: [abcd1234] Reasons: [body] Reflection: [False]"
                    in e.data["description"]
                ):
                    found_hidden_getparam_recycled = True

                if (
                    "http://127.0.0.1:8888/test2.pdf" in e.data["url"]
                    and "[Paramminer] Getparam: [abcd1234] Reasons: [body] Reflection: [False]"
                    in e.data["description"]
                ):
                    emitted_excavate_paramminer_duplicate = True

        assert found_hidden_getparam_recycled, "Failed to find hidden GET parameter"
        assert not emitted_excavate_paramminer_duplicate, "Paramminer emitted parameter for static URL"
