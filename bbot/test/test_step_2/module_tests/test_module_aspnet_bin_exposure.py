from .base import ModuleTestBase
import re
from bbot.test.worker import HTTPSERVER_URL


class TestAspnetBinExposure(ModuleTestBase):
    """Only technique 1 is vulnerable; technique 2 returns 404.

    A tracker mis-correlation would either build the confirm URL from the
    wrong technique pattern (hitting the 404 fallback) or attribute technique
    2's 404 result to technique 1 (skipping detection). Either way the
    assertion on the Detection Url pattern would fail.
    """

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "aspnet_bin_exposure"]

    async def setup_before_prep(self, module_test):
        # Technique 1: vulnerable (200 + DLL content-type)
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/b/(S(X))in/Newtonsoft.Json.dll/(S(X))/"},
            respond_args={
                "status": 200,
                "headers": {"content-type": "application/x-msdownload"},
                "response_data": b"MZ\x90\x00\x03\x00\x00\x00",
            },
        )

        # Technique 1: confirm (fake DLL -> 404 = genuine vulnerability)
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/b/(S(X))in/oopsnotarealdll.dll/(S(X))/"},
            respond_args={"status": 404},
        )

        # Everything else (technique 2 probes, other DLLs) -> 404
        module_test.set_expect_requests(
            expect_args={"uri": re.compile(r"^/.*$")},
            respond_args={"status": 404},
        )

    def check(self, module_test, events):
        findings = [
            e for e in events if e.type == "FINDING" and "IIS Bin Directory DLL Exposure" in e.data["description"]
        ]
        assert len(findings) == 1, f"Expected exactly 1 finding, got {len(findings)}"
        finding = findings[0]
        assert finding.data["severity"] == "HIGH"
        assert "b/(S(X))in/" in finding.data["description"], (
            f"Detection Url should use technique 1 pattern, got: {finding.data['description']}"
        )


class TestAspnetBinExposure_DeadHost(ModuleTestBase):
    """Dead host returns 404 for everything -- no FINDING should be emitted."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "aspnet_bin_exposure"]

    async def setup_before_prep(self, module_test):
        expect_args = {"uri": re.compile(r"^/.*$")}
        respond_args = {"status": 404}
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 0, f"Dead host should not produce findings, got: {findings}"


class TestAspnetBinExposure_FalsePositive(ModuleTestBase):
    """Host serves DLLs for everything (including the fake DLL) -- no FINDING should be emitted."""

    targets = [HTTPSERVER_URL]
    modules_overrides = ["http", "aspnet_bin_exposure"]

    async def setup_before_prep(self, module_test):
        expect_args = {"uri": re.compile(r"^/.*$")}
        respond_args = {
            "status": 200,
            "headers": {"content-type": "application/x-msdownload"},
            "response_data": b"MZ\x90\x00\x03\x00\x00\x00",
        }
        module_test.set_expect_requests(expect_args=expect_args, respond_args=respond_args)

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING"]
        assert len(findings) == 0, (
            f"Host that serves DLLs for everything (including fake DLL) should not produce findings, got: {findings}"
        )
