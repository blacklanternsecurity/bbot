from pathlib import Path
from .base import ModuleTestBase, tempwordlist
import pytest


@pytest.fixture(params=["ssh", "ftp", "telnet", "vnc", "mssql", "mysql", "postgresql"])
def protocol(request):
    return request.param


@pytest.fixture
def mock_legba_run_process(monkeypatch, request):
    async def fake_run_process(self, cmd):
        try:
            # find index of `--output` in cmd
            output_index = cmd.index("--output")
            # output_path is directly after `--output` in cmd
            output_path = Path(cmd[output_index + 1])
        except Exception as e:
            raise Exception(f"Could not determine output file path from command {cmd}: {e}")

        protocol = request.getfixturevalue("protocol")

        expected_file_content_per_protocol = {
            "ssh": '{"found_at":"2025-07-22T20:50:19.541305293+02:00","target":"127.0.0.1:2222","plugin":"ssh","data":{"username":"remnux","password":"malware"},"partial":false}',
            "ftp": '{"found_at":"2025-07-22T20:51:19.541305293+02:00","target":"127.0.0.1:21","plugin":"ftp","data":{"username":"ftp_boot","password":"ftp_boot"},"partial":false}',
            "telnet": '{"found_at":"2025-07-22T20:51:19.541305293+02:00","target":"127.0.0.1:23","plugin":"telnet","data":{"username":"guest","password":"guest"},"partial":false}',
            "vnc": '{"found_at":"2025-07-22T20:51:19.541305293+02:00","target":"127.0.0.1:5900","plugin":"vnc","data":{"username":"Administrator","password":""},"partial":false}',
            "mssql": '{"found_at":"2025-07-22T20:51:19.541305293+02:00","target":"127.0.0.1:1433","plugin":"mssql","data":{"username":"sa","password":"default"},"partial":false}',
            "mysql": '{"found_at":"2025-07-22T20:51:19.541305293+02:00","target":"127.0.0.1:3306","plugin":"mysql","data":{"username":"root","password":"moves"},"partial":false}',
            "postgresql": '{"found_at":"2025-07-22T20:51:19.541305293+02:00","target":"127.0.0.1:5432","plugin":"pgsql","data":{"username":"postgres","password":"postgres"},"partial":false}',
        }

        output_path.write_text(expected_file_content_per_protocol[protocol])

    from bbot.modules.base import BaseModule

    monkeypatch.setattr(BaseModule, "run_process", fake_run_process)


@pytest.mark.usefixtures("mock_legba_run_process")
class TestLegba(ModuleTestBase):
    targets = ["127.0.0.1"]

    temp_ssh_wordlist = tempwordlist(["test:test", "admin:admin", "admin:password", "remnux:malware", "user:pass"])
    temp_ftp_wordlist = tempwordlist(["test:test", "ftp_boot:ftp_boot", "admin:password", "root:root", "user:pass"])
    temp_telnet_wordlist = tempwordlist(["test:test", "admin:admin", "admin:password", "root:root", "guest:guest"])
    temp_vnc_wordlist = tempwordlist(["test", "admin", "password", "Administrator", "pass"])
    temp_mssql_wordlist = tempwordlist(["sa:default", "admin:admin", "admin:password", "root:root", "user:pass"])
    temp_mysql_wordlist = tempwordlist(["test:test", "admin:admin", "root:moves", "root:root", "user:pass"])
    temp_postgresql_wordlist = tempwordlist(["postgres:postgres", "admin:admin", "admin:password", "user:pass"])

    config_overrides = {
        "modules": {
            "legba": {
                "ssh_wordlist": str(temp_ssh_wordlist),
                "ftp_wordlist": str(temp_ftp_wordlist),
                "telnet_wordlist": str(temp_telnet_wordlist),
                "vnc_wordlist": str(temp_vnc_wordlist),
                "mssql_wordlist": str(temp_mssql_wordlist),
                "mysql_wordlist": str(temp_mysql_wordlist),
                "postgresql_wordlist": str(temp_postgresql_wordlist),
            }
        }
    }

    @pytest.fixture(autouse=True)
    def _protocol_dependency(self, protocol):
        # ensure pytest sees dependency and runs one test per protocol
        self._protocol = protocol

    async def setup_after_prep(self, module_test):
        protocol = module_test.request_fixture.getfixturevalue("protocol")
        ports = {"ssh": 2222, "ftp": 21, "telnet": 23, "vnc": 5900, "mssql": 1433, "mysql": 3306, "postgresql": 5432}
        event_data = {"host": str(self.targets[0]), "protocol": protocol.upper(), "port": ports[protocol]}
        protocol_event = module_test.scan.make_event(
            event_data,
            "PROTOCOL",
            parent=module_test.scan.root_event,
        )

        await module_test.module.emit_event(protocol_event)

    def check(self, module_test, events):
        protocol = module_test.request_fixture.getfixturevalue("protocol")
        finding_events = [e for e in events if e.type == "FINDING"]

        assert len(finding_events) == 1

        expected_desc = {
            "ssh": "Valid ssh credentials found - remnux:malware",
            "ftp": "Valid ftp credentials found - ftp_boot:ftp_boot",
            "telnet": "Valid telnet credentials found - guest:guest",
            "vnc": "Valid vnc credentials found - Administrator",
            "mssql": "Valid mssql credentials found - sa:default",
            "mysql": "Valid mysql credentials found - root:moves",
            "postgresql": "Valid postgresql credentials found - postgres:postgres",
        }

        assert expected_desc[protocol] in finding_events[0].data["description"]
