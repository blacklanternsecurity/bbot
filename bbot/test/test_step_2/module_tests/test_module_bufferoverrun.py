from .base import ModuleTestBase


class TestBufferOverrun(ModuleTestBase):
    config_overrides = {"modules": {"bufferoverrun": {"api_key": "asdf", "commercial": False}}}

    async def setup_before_prep(self, module_test):
        # Mock response for non-commercial API
        module_test.httpx_mock.add_response(
            url="https://tls.bufferover.run/dns?q=.blacklanternsecurity.com",
            match_headers={"x-api-key": "asdf"},
            json={"Results": ["1.2.3.4,example.com,*,*,sub.blacklanternsecurity.com"]},
        )

    def check(self, module_test, events):
        assert any(e.data == "sub.blacklanternsecurity.com" for e in events), "Failed to detect subdomain for free API"


class TestBufferOverrunCommercial(ModuleTestBase):
    modules_overrides = ["bufferoverrun"]
    module_name = "bufferoverrun"
    config_overrides = {"modules": {"bufferoverrun": {"api_key": "asdf", "commercial": True}}}

    async def setup_before_prep(self, module_test):
        # Mock response for commercial API
        module_test.httpx_mock.add_response(
            url="https://bufferover-run-tls.p.rapidapi.com/ipv4/dns?q=.blacklanternsecurity.com",
            match_headers={"x-rapidapi-host": "bufferover-run-tls.p.rapidapi.com", "x-rapidapi-key": "asdf"},
            json={"Results": ["5.6.7.8,blacklanternsecurity.com,*,*,sub.blacklanternsecurity.com"]},
        )

    def check(self, module_test, events):
        assert any(
            e.data == "sub.blacklanternsecurity.com" for e in events
        ), "Failed to detect subdomain for commercial API"
