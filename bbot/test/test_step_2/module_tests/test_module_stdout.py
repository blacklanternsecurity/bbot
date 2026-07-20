import json

from .base import ModuleTestBase


class TestStdout(ModuleTestBase):
    modules_overrides = ["stdout"]

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        assert out.startswith("[SCAN]              \tteststdout")
        assert "[DNS_NAME]          \tblacklanternsecurity.com\tSEED" in out


class TestStdoutEventTypes(TestStdout):
    config_overrides = {"modules": {"stdout": {"event_types": ["DNS_NAME"]}}}

    def check(self, module_test, events):
        out, err = module_test.capsys.readouterr()
        assert len(out.splitlines()) == 1
        assert out.startswith("[DNS_NAME]          \tblacklanternsecurity.com\tSEED")


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


class TestStdoutFindingColor(TestStdout):
    module_name = "stdout"

    def check(self, module_test, events):
        module = module_test.module
        # coloring is disabled when stdout isn't a terminal (as in captured test output)
        assert module.use_color is False

        # CRITICAL is purple (207,0,255); CONFIRMED is full brightness + bold
        critical = module_test.scan.make_event(
            {
                "host": "evilcorp.com",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "description": "asdf",
                "name": "Test",
            },
            "FINDING",
            dummy=True,
        )
        colored = module._colorize_finding("test", critical)
        assert colored == "\033[1;38;2;207;0;255mtest\033[0m"

        # INFO is blue (113,161,255) dimmed to 0.55 brightness, no bold
        info = module_test.scan.make_event(
            {
                "host": "evilcorp.com",
                "severity": "INFO",
                "confidence": "UNKNOWN",
                "description": "asdf",
                "name": "Test",
            },
            "FINDING",
            dummy=True,
        )
        colored_info = module._colorize_finding("test", info)
        assert colored_info == "\033[38;2;62;88;140mtest\033[0m"


class TestStdoutControlChars(TestStdout):
    module_name = "stdout"

    async def check(self, module_test, events):
        module = module_test.module
        # a FINDING whose description carries a raw 0x0e (Shift Out), as matched response content can
        finding = module_test.scan.make_event(
            {
                "host": "evilcorp.com",
                "severity": "INFO",
                "confidence": "UNKNOWN",
                "name": "Test",
                "description": "matched banner \x0e deadbeef",
            },
            "FINDING",
            dummy=True,
        )
        # sanity: the raw control byte really does reach the human-readable string
        assert "\x0e" in module.human_event_str(finding)

        module_test.capsys.readouterr()  # discard captured scan output
        await module.handle_text(finding, finding.json(mode="human"))
        out, err = module_test.capsys.readouterr()
        # the byte that would flip the terminal into its line-drawing charset is escaped, not printed raw
        assert "\x0e" not in out
        assert "\\x0e" in out


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
