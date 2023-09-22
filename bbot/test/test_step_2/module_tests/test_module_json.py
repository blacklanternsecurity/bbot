import json

from .base import ModuleTestBase
from bbot.core.event.base import event_from_json


class TestJSON(ModuleTestBase):
    def check(self, module_test, events):
        txt_file = module_test.scan.home / "output.ndjson"
        lines = list(module_test.scan.helpers.read_file(txt_file))
        assert lines
        json_event = json.loads(lines[0])
        assert json_event["type"] == "SCAN"
        assert json_event["data"] == {"SCAN": f"{module_test.scan.name} ({module_test.scan.id})"}
        e = event_from_json(json_event)
        assert e.type == "SCAN"
        assert e.data == f"{module_test.scan.name} ({module_test.scan.id})"
