from .base import ModuleTestBase


class TestWayback(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original",
            json=[["original"], ["http://asdf.blacklanternsecurity.com"]],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestWaybackParameters(ModuleTestBase):
    module_name = "wayback"
    modules_overrides = ["wayback", "hunt"]
    whitelist = ["blacklanternsecurity.com", "127.0.0.1"]
    config_overrides = {"modules": {"wayback": {"urls": True, "parameters": True}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="http://web.archive.org/cdx/search/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fl=original&collapse=original",
            json=[
                ["original"],
                ["http://127.0.0.1:8888/page?foo=bar&baz=qux"],
            ],
        )
        # serve a response on the local httpserver so the httpx binary gets a 200
        module_test.set_expect_requests(expect_args={"uri": "/page"}, respond_args={"response_data": "alive"})

    def check(self, module_test, events):
        assert any(e.type == "URL_UNVERIFIED" and "127.0.0.1" in e.data and "/page" in e.data for e in events), (
            "Failed to emit URL_UNVERIFIED"
        )
        assert any(
            e.type == "WEB_PARAMETER" and e.data["name"] == "foo" and e.data["original_value"] == "bar" for e in events
        ), "Failed to emit WEB_PARAMETER for foo"
        assert any(
            e.type == "WEB_PARAMETER" and e.data["name"] == "baz" and e.data["original_value"] == "qux" for e in events
        ), "Failed to emit WEB_PARAMETER for baz"
        # check that additional_params contains sibling params but excludes the current one
        for e in events:
            if e.type == "WEB_PARAMETER" and e.data["name"] == "foo":
                assert e.data["additional_params"] == {"baz": "qux"}, (
                    f"foo's additional_params wrong: {e.data['additional_params']}"
                )
            if e.type == "WEB_PARAMETER" and e.data["name"] == "baz":
                assert e.data["additional_params"] == {"foo": "bar"}, (
                    f"baz's additional_params wrong: {e.data['additional_params']}"
                )
