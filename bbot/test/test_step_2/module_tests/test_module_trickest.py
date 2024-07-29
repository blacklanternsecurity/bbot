from .base import ModuleTestBase


class TestTrickest(ModuleTestBase):
    config_overrides = {"modules": {"trickest": {"api_key": "deadbeef"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/dataset",
            match_headers={"Authorization": "Token deadbeef"},
            json={},
        )
        module_test.httpx_mock.add_response(
            url="https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/view?q=hostname%20~%20%22.blacklanternsecurity.com%22&dataset_id=a0a49ca9-03bb-45e0-aa9a-ad59082ebdfc&limit=50&offset=0&select=hostname&orderby=hostname",
            match_headers={"Authorization": "Token deadbeef"},
            json={"results": [{"hostname": "asdf.blacklanternsecurity.com"}]},
        )
        module_test.httpx_mock.add_response(
            url="https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be/view?q=hostname%20~%20%22.blacklanternsecurity.com%22&dataset_id=a0a49ca9-03bb-45e0-aa9a-ad59082ebdfc&limit=50&offset=50&select=hostname&orderby=hostname",
            match_headers={"Authorization": "Token deadbeef"},
            json={"results": [{"hostname": "www.blacklanternsecurity.com"}]},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "www.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
