import json

from .base import ModuleTestBase
from bbot.core.event.base import event_from_json


class TestJSON(ModuleTestBase):
    def check(self, module_test, events):
        txt_file = module_test.scan.home / "output.json"
        lines = list(module_test.scan.helpers.read_file(txt_file))
        assert lines
        e = event_from_json(json.loads(lines[0]))
        assert e.type == "SCAN"
        assert e.data == f"{module_test.scan.name} ({module_test.scan.id})"
