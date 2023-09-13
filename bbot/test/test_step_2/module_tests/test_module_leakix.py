from .base import ModuleTestBase


class TestLeakIX(ModuleTestBase):
    config_overrides = {"modules": {"leakix": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://leakix.net/host/1.2.3.4.5",
            match_headers={"api-key": "asdf"},
            json={"title": "Not Found", "description": "Host not found"},
        )
        module_test.httpx_mock.add_response(
            url=f"https://leakix.net/api/subdomains/blacklanternsecurity.com",
            match_headers={"api-key": "asdf"},
            json=[
                {
                    "subdomain": "asdf.blacklanternsecurity.com",
                    "distinct_ips": 3,
                    "last_seen": "2023-04-02T09:38:30.02Z",
                },
            ],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"


class TestLeakIX_NoAPIKey(ModuleTestBase):
    modules_overrides = ["leakix"]

    async def setup_before_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url=f"https://leakix.net/api/subdomains/blacklanternsecurity.com",
            json=[
                {
                    "subdomain": "asdf.blacklanternsecurity.com",
                    "distinct_ips": 3,
                    "last_seen": "2023-04-02T09:38:30.02Z",
                },
            ],
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
