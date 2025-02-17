from .base import ModuleTestBase, tempwordlist


class TestFFUF(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    test_wordlist = ["11111111", "admin", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {
            "ffuf": {
                "wordlist": tempwordlist(test_wordlist),
            }
        }
    }
    modules_overrides = ["ffuf", "httpx"]

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/admin"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "admin" in e.data for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "11111111" in e.data for e in events)


class TestFFUF2(TestFFUF):
    test_wordlist = ["11111111", "console", "junkword1", "zzzjunkword2"]
    config_overrides = {"modules": {"ffuf": {"wordlist": tempwordlist(test_wordlist), "extensions": "php"}}}

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/console.php"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "console" in e.data for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "11111111" in e.data for e in events)


class TestFFUF_ignorecase(TestFFUF):
    test_wordlist = ["11111111", "Admin", "admin", "zzzjunkword2"]
    config_overrides = {
        "modules": {"ffuf": {"wordlist": tempwordlist(test_wordlist), "extensions": "php", "ignore_case": True}}
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "uri": "/admin"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/Admin"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "admin" in e.data for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "Admin" in e.data for e in events)


class TestFFUFHeaders(TestFFUF):
    test_wordlist = ["11111111", "console", "junkword1", "zzzjunkword2"]
    config_overrides = {
        "modules": {"ffuf": {"wordlist": tempwordlist(test_wordlist), "extensions": "php"}},
        "web": {"http_headers": {"test": "test2"}},
    }

    async def setup_before_prep(self, module_test):
        expect_args = {"method": "GET", "headers": {"test": "test2"}, "uri": "/console.php"}
        respond_args = {"response_data": "alive admin page"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        expect_args = {"method": "GET", "uri": "/"}
        respond_args = {"response_data": "alive"}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "console" in e.data for e in events)
        assert not any(e.type == "URL_UNVERIFIED" and "11111111" in e.data for e in events)
