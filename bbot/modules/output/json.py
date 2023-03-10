import json
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class JSON(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to JSON"}
    options = {"output_file": "", "console": False}
    options_desc = {"output_file": "Output to file", "console": "Output to console"}

    def setup(self):
        self._prep_output_dir("output.json")
        return True

    def handle_event(self, event):
        event_str = json.dumps(dict(event))
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        if self.config.get("console", False) or "human" not in self.scan.modules:
            self.stdout(event_str)

    def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    def report(self):
        if self._file is not None:
            self.info(f"Saved JSON output to {self.output_file}")
