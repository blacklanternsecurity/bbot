import json

from .base import ModuleTestBase


class TestStdout(ModuleTestBase):
    modules_overrides = ["stdout"]

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        assert out.startswith("[SCAN]              \tteststdout")
        assert "[DNS_NAME]          \tblacklanternsecurity.com\tTARGET" in out


class TestStdoutEventTypes(TestStdout):
    config_overrides = {"modules": {"stdout": {"event_types": ["DNS_NAME"]}}}

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        assert len(out.splitlines()) == 1
        assert out.startswith("[DNS_NAME]          \tblacklanternsecurity.com\tTARGET")


class TestStdoutEventFields(TestStdout):
    config_overrides = {"modules": {"stdout": {"event_types": ["DNS_NAME"], "event_fields": ["data"]}}}

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        assert out == "blacklanternsecurity.com\n"


class TestStdoutJSON(TestStdout):
    config_overrides = {
        "modules": {
            "stdout": {
                "format": "json",
            }
        }
    }

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        lines = out.splitlines()
        assert len(lines) == 3
        for i, line in enumerate(lines):
            event = json.loads(line)
            if i == 0:
                assert event["type"] == "SCAN"
            elif i == 1:
                assert event["type"] == "DNS_NAME" and event["data"] == "blacklanternsecurity.com"
            if i == 2:
                assert event["type"] == "SCAN"


class TestStdoutJSONFields(TestStdout):
    config_overrides = {"modules": {"stdout": {"format": "json", "event_fields": ["data", "module_sequence"]}}}

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        lines = out.splitlines()
        assert len(lines) == 3
        for line in lines:
            event = json.loads(line)
            assert set(event) == {"data", "module_sequence"}


class TestStdoutDupes(TestStdout):
    targets = ["blacklanternsecurity.com", "127.0.0.2"]
    config_overrides = {
        "dns": {"minimal": False},
        "modules": {
            "stdout": {
                "event_types": ["DNS_NAME", "IP_ADDRESS"],
            }
        },
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.2"]}})

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        lines = out.splitlines()
        assert len(lines) == 3
        assert out.count("[IP_ADDRESS]        \t127.0.0.2") == 2


class TestStdoutNoDupes(TestStdoutDupes):
    config_overrides = {
        "dns": {"minimal": False},
        "modules": {
            "stdout": {
                "event_types": ["DNS_NAME", "IP_ADDRESS"],
                "accept_dupes": False,
            }
        },
    }

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        lines = out.splitlines()
        assert len(lines) == 2
        assert out.count("[IP_ADDRESS]        \t127.0.0.2") == 1
