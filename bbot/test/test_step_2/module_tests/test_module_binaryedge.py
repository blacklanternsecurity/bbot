from .base import ModuleTestBase


class TestBinaryEdge(ModuleTestBase):
    config_overrides = {"modules": {"binaryedge": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://api.binaryedge.io/v2/query/domains/subdomain/blacklanternsecurity.com",
            json={
                "query": "blacklanternsecurity.com",
                "page": 1,
                "pagesize": 100,
                "total": 1,
                "events": [
                    "asdf.blacklanternsecurity.com",
                ],
            },
        )
        module_test.httpx_mock.add_response(
            url=f"https://api.binaryedge.io/v2/user/subscription",
            json={
                "subscription": {"name": "Free"},
                "end_date": "2023-06-17",
                "requests_left": 249,
                "requests_plan": 250,
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
