import json

from .base import ModuleTestBase
from bbot.core.event.base import event_from_json


class TestJSON(ModuleTestBase):
    def check(self, module_test, events):
        dns_data = "blacklanternsecurity.com"
        context_data = f"Scan {module_test.scan.name} seeded with DNS_NAME: blacklanternsecurity.com"

        scan_event = [e for e in events if e.type == "SCAN"][0]
        dns_event = [e for e in events if e.type == "DNS_NAME"][0]

        # json events
        txt_file = module_test.scan.home / "output.json"
        lines = list(module_test.scan.helpers.read_file(txt_file))
        assert lines
        json_events = [json.loads(line) for line in lines]
        scan_json = [e for e in json_events if e["type"] == "SCAN"]
        dns_json = [e for e in json_events if e["type"] == "DNS_NAME"]
        assert len(scan_json) == 2
        assert len(dns_json) == 1
        dns_json = dns_json[0]
        scan = scan_json[0]
        assert scan["data"]["name"] == module_test.scan.name
        assert scan["data"]["id"] == module_test.scan.id
        assert scan["id"] == module_test.scan.id
        assert scan["uuid"] == str(module_test.scan.root_event.uuid)
        assert scan["parent_uuid"] == str(module_test.scan.root_event.uuid)
        assert scan["data"]["target"]["seeds"] == ["blacklanternsecurity.com"]
        assert scan["data"]["target"]["whitelist"] == ["blacklanternsecurity.com"]
        assert dns_json["data"] == dns_data
        assert dns_json["id"] == str(dns_event.id)
        assert dns_json["uuid"] == str(dns_event.uuid)
        assert dns_json["parent_uuid"] == str(module_test.scan.root_event.uuid)
        assert dns_json["discovery_context"] == context_data
        assert dns_json["discovery_path"] == [context_data]
        assert dns_json["parent_chain"] == [dns_json["uuid"]]

        # event objects reconstructed from json
        scan_reconstructed = event_from_json(scan_json[0])
        dns_reconstructed = event_from_json(dns_json)
        assert scan_reconstructed.data["name"] == module_test.scan.name
        assert scan_reconstructed.data["id"] == module_test.scan.id
        assert scan_reconstructed.uuid == scan_event.uuid
        assert scan_reconstructed.parent_uuid == scan_event.uuid
        assert scan_reconstructed.data["target"]["seeds"] == ["blacklanternsecurity.com"]
        assert scan_reconstructed.data["target"]["whitelist"] == ["blacklanternsecurity.com"]
        assert dns_reconstructed.data == dns_data
        assert dns_reconstructed.uuid == dns_event.uuid
        assert dns_reconstructed.parent_uuid == module_test.scan.root_event.uuid
        assert dns_reconstructed.discovery_context == context_data
        assert dns_reconstructed.discovery_path == [context_data]
        assert dns_reconstructed.parent_chain == [dns_json["uuid"]]


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
