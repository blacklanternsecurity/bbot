import json

from .base import ModuleTestBase
from bbot.core.event.base import event_from_json


class TestJSON(ModuleTestBase):
    def check(self, module_test, events):
        dns_data = "blacklanternsecurity.com"
        context_data = f"Scan {module_test.scan.name} seeded with DNS_NAME: blacklanternsecurity.com"

        # json events
        txt_file = module_test.scan.home / "output.json"
        lines = list(module_test.scan.helpers.read_file(txt_file))
        assert lines
        json_events = [json.loads(line) for line in lines]
        scan_json = [e for e in json_events if e["type"] == "SCAN"]
        dns_json = [e for e in json_events if e["type"] == "DNS_NAME"]
        assert len(scan_json) == 1
        assert len(dns_json) == 1
        scan_json = scan_json[0]
        dns_json = dns_json[0]
        assert scan_json["data"]["name"] == module_test.scan.name
        assert scan_json["data"]["id"] == module_test.scan.id
        assert scan_json["data"]["target"]["seeds"] == ["blacklanternsecurity.com"]
        assert scan_json["data"]["target"]["whitelist"] == ["blacklanternsecurity.com"]
        assert dns_json["data"] == dns_data
        assert dns_json["discovery_context"] == context_data
        assert dns_json["discovery_path"] == [["DNS_NAME:1e57014aa7b0715bca68e4f597204fc4e1e851fc", context_data]]

        # event objects reconstructed from json
        scan_reconstructed = event_from_json(scan_json)
        dns_reconstructed = event_from_json(dns_json)
        assert scan_reconstructed.data["name"] == module_test.scan.name
        assert scan_reconstructed.data["id"] == module_test.scan.id
        assert scan_reconstructed.data["target"]["seeds"] == ["blacklanternsecurity.com"]
        assert scan_reconstructed.data["target"]["whitelist"] == ["blacklanternsecurity.com"]
        assert dns_reconstructed.data == dns_data
        assert dns_reconstructed.discovery_context == context_data
        assert dns_reconstructed.discovery_path == [
            ["DNS_NAME:1e57014aa7b0715bca68e4f597204fc4e1e851fc", context_data]
        ]


class TestJSONSIEMFriendly(ModuleTestBase):
    modules_overrides = ["json"]
    config_overrides = {"modules": {"json": {"siem_friendly": True}}}

    def check(self, module_test, events):
        txt_file = module_test.scan.home / "output.json"
        lines = list(module_test.scan.helpers.read_file(txt_file))
        passed = False
        for line in lines:
            e = json.loads(line)
            if e["data"] == {"DNS_NAME": "blacklanternsecurity.com"}:
                passed = True
        assert passed
