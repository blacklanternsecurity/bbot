from .base import ModuleTestBase


class TestZoomEye(ModuleTestBase):
    config_overrides = {"modules": {"zoomeye": {"api_key": "asdf", "include_related": True, "max_pages": 3}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.zoomeye.hk/resources-info",
            match_headers={"API-KEY": "asdf"},
            json={"quota_info": {"remain_total_quota": 5}},
        )
        module_test.httpx_mock.add_response(
            url="https://api.zoomeye.hk/domain/search?q=blacklanternsecurity.com&type=0&page=1",
            json={"list": [{"name": "asdf.blacklanternsecurity.com"}]},
        )
        module_test.httpx_mock.add_response(
            url="https://api.zoomeye.hk/domain/search?q=blacklanternsecurity.com&type=0&page=2",
            json={"list": [{"name": "zzzz.blacklanternsecurity.com"}]},
        )
        module_test.httpx_mock.add_response(
            url="https://api.zoomeye.hk/domain/search?q=blacklanternsecurity.com&type=0&page=3",
            json={"list": [{"name": "ffff.blacklanternsecurity.com"}, {"name": "affiliate.bls"}]},
        )
        module_test.httpx_mock.add_response(
            url="https://api.zoomeye.hk/domain/search?q=blacklanternsecurity.com&type=0&page=4",
            json={"list": [{"name": "nope.blacklanternsecurity.com"}]},
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain #1"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to detect subdomain #2"
        assert any(e.data == "ffff.blacklanternsecurity.com" for e in events), "Failed to detect subdomain #3"
        assert any(e.data == "affiliate.bls" and "affiliate" in e.tags for e in events), "Failed to detect affiliate"
        assert not any(e.data == "nope.blacklanternsecurity.com" for e in events), "Failed to obey max_pages"
