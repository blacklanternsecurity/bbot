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
        assert scan["data_json"]["name"] == module_test.scan.name
        assert scan["data_json"]["id"] == module_test.scan.id
        assert scan["id"] == module_test.scan.id
        assert scan["uuid"] == str(module_test.scan.root_event.uuid)
        assert scan["parent_uuid"] == str(module_test.scan.root_event.uuid)
        assert not "seeds" in scan["data_json"]["target"], "seeds should not be in target json"
        assert scan["data_json"]["target"]["target"] == ["blacklanternsecurity.com"]
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
        assert not "seeds" in scan_reconstructed.data["target"], "seeds should not be in target json"
        assert scan_reconstructed.data["target"]["target"] == ["blacklanternsecurity.com"]
        assert dns_reconstructed.data == dns_data
        assert dns_reconstructed.uuid == dns_event.uuid
        assert dns_reconstructed.parent_uuid == module_test.scan.root_event.uuid
        assert dns_reconstructed.discovery_context == context_data
        assert dns_reconstructed.discovery_path == [context_data]
        assert dns_reconstructed.parent_chain == [dns_json["uuid"]]


class TestJSONGraphOrphanJSURL(ModuleTestBase):
    """
    Reproducer for https://github.com/blacklanternsecurity/bbot/issues/1151

    JS URLs get _omit=True (URL_UNVERIFIED is in default omit_event_types) and
    _internal=True (.js is a special extension). If a graph-worthy event is
    discovered with a JS URL ancestor, every event in the JSON output must
    reference a parent that is also in the output (no orphans).
    """

    targets = ["http://127.0.0.1:8888"]
    modules_overrides = ["http", "excavate", "json"]
    # The test conf clears omit_event_types — restore the production default so
    # URL_UNVERIFIED (which JS URLs use) actually gets _omit=True by ScanEgress.
    config_overrides = {
        "scope": {"report_distance": 2},
        "web": {"spider_distance": 5, "spider_depth": 5},
        "omit_event_types": [
            "HTTP_RESPONSE",
            "RAW_TEXT",
            "URL_UNVERIFIED",
            "DNS_NAME_UNRESOLVED",
            "FILESYSTEM",
            "WEB_PARAMETER",
            "RAW_DNS_RECORD",
        ],
    }

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"},
            respond_args={
                "response_data": "<html><body><script src='http://127.0.0.1:8888/asdf.js'></script></body></html>",
                "headers": {"Content-Type": "text/html"},
            },
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/asdf.js"},
            respond_args={
                "response_data": "var leak = 'http://orphan-test.evilcorp.com/path';",
                "headers": {"Content-Type": "application/javascript"},
            },
        )

    def check(self, module_test, events):
        txt_file = module_test.scan.home / "output.json"
        lines = list(module_test.scan.helpers.read_file(txt_file))
        assert lines, "json output is empty"
        json_events = [json.loads(line) for line in lines]

        uuids = {e["uuid"] for e in json_events}
        orphans = []
        for e in json_events:
            parent_uuid = e.get("parent_uuid")
            if parent_uuid and parent_uuid not in uuids:
                orphans.append((e["type"], e.get("data"), parent_uuid))

        assert not orphans, f"found {len(orphans)} graph orphan(s) — parent_uuid not present in output:\n" + "\n".join(
            f"  - {t}: {d!r} -> missing parent {p}" for t, d, p in orphans
        )

        # sanity: scan must have actually walked the JS chain
        all_text = "\n".join(lines)
        assert ".js" in all_text or "asdf" in all_text, (
            f"test scenario did not exercise the JS URL chain. JSON contents:\n{all_text}"
        )
