from .base import ModuleTestBase, tempwordlist
import pytest


@pytest.fixture
def mock_medusa_run_process(monkeypatch):
    async def fake_run_process(self, cmd):
        class FakeResult:
            stdout = "ACCOUNT FOUND: [snmp] Host: 127.0.0.1 User: (null) Password: public [ERROR]\n"
            stderr = (
                "ERROR: [snmp.mod] Error processing SNMP response (1).\n"
                "ERROR: [snmp.mod] Community string appears to have only READ access.\n"
            )

        return FakeResult()

    from bbot.modules.base import BaseModule

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)


@pytest.mark.usefixtures("mock_medusa_run_process")
class TestMedusa(ModuleTestBase):
    targets = ["127.0.0.1"]
    temp_snmp_wordlist = tempwordlist(["public", "private, admin"])
    config_overrides = {
        "modules": {
            "medusa": {
                "snmp_versions": ["2C"],
                "timeout_s": 1,
                "snmp_wordlist": str(temp_snmp_wordlist),
            }
        }
    }

    async def setup_after_prep(self, module_test):
        protocol_data = {"host": str(self.targets[0]), "protocol": "snmp", "port": 161}

        protocol_event = module_test.scan.make_event(
            protocol_data,
            "PROTOCOL",
            parent=module_test.scan.root_event,
        )
        await module_test.module.emit_event(protocol_event)

    def check(self, module_test, events):
        vuln_events = [e for e in events if e.type == "VULNERABILITY"]

        assert len(vuln_events) == 1
        assert "VALID [SNMPV2C] CREDENTIALS FOUND: public [READ]" in vuln_events[0].data["description"]
