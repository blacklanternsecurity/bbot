from .base import ModuleTestBase
import re


class TestAspnetBinExposure(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["httpx", "aspnet_bin_exposure"]
    config_overrides = {
        "modules": {
            "aspnet_bin_exposure": {
                "test_dlls": [
                    "Newtonsoft.Json.dll",
                ]
            }
        }
    }

    async def setup_before_prep(self, module_test):
        # Simulate successful DLL exposure
        expect_args = {
            "method": "GET",
            "uri": "/b/(S(X))in/Newtonsoft.Json.dll/(S(X))/",
        }
        respond_args = {
            "status": 200,
            "headers": {"content-type": "application/x-msdownload"},
            "response_data": b"MZ\x90\x00\x03\x00\x00\x00",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate failed DLL exposure (confirmation test)
        expect_args = {
            "method": "GET",
            "uri": "/b/(S(X))in/oopsnotarealdll.dll/(S(X))/",
        }
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate alternative technique
        expect_args = {
            "method": "GET",
            "uri": "/(S(X))/b/(S(X))in/Newtonsoft.Json.dll",
        }
        respond_args = {
            "status": 200,
            "headers": {"content-type": "application/x-msdownload"},
            "response_data": b"MZ\x90\x00\x03\x00\x00\x00",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Simulate failed alternative technique (confirmation test)
        expect_args = {
            "method": "GET",
            "uri": "/(S(X))/b/(S(X))in/oopsnotarealdll.dll",
        }
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

        # Fallback for any other requests
        expect_args = {"uri": re.compile(r"^/.*$")}
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        vulnerability_found = False
        for e in events:
            if e.type == "VULNERABILITY" and "IIS Bin Directory DLL Exposure" in e.data["description"]:
                vulnerability_found = True
                assert e.data["severity"] == "HIGH", "Vulnerability severity should be HIGH"
                assert "Detection Url" in e.data["description"], "Description should include detection URL"
                break

        assert vulnerability_found, "No vulnerability event was found"
