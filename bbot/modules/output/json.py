import json
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class JSON(BaseOutputModule):
    watched_events = ["*"]
    meta = {
        "description": "Output to Newline-Delimited JSON (NDJSON)",
        "created_date": "2022-04-07",
        "author": "@TheTechromancer",
    }
    options = {"output_file": ""}
    options_desc = {
        "output_file": "Output to file",
    }
    _preserve_graph = True

    async def setup(self):
        self._prep_output_dir("output.json")
        return True

    async def handle_event(self, event):
        event_json = event.json()
        event_str = json.dumps(event_json)
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if self._file is not None:
            self.info(f"Saved JSON output to {self.output_file}")
