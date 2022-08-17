import json
from pathlib import Path
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class JSON(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to JSON"}
    options = {"output_file": "", "console": False}
    options_desc = {"output_file": "Output to file", "console": "Output to console"}

    def setup(self):
        self.output_file = self.config.get("output_file", "")
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / "output.json"
        self.helpers.mkdir(self.output_file.parent)
        self._file = None
        return True

    @property
    def file(self):
        if self._file is None:
            self._file = open(self.output_file, mode="a")
        return self._file

    def handle_event(self, event):
        event_str = json.dumps(dict(event))
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        if self.config.get("console", False) or "human" not in self.scan.modules:
            self.stdout(event_str)

    def cleanup(self):
        if self._file is not None:
            with suppress(Exception):
                self.file.close()
