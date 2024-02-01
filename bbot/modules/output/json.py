import json
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class JSON(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to Newline-Delimited JSON (NDJSON)"}
    options = {"output_file": "", "console": False, "siem_friendly": False}
    options_desc = {
        "output_file": "Output to file",
        "console": "Output to console",
        "siem_friendly": "Output JSON in a SIEM-friendly format for ingestion into Elastic, Splunk, etc.",
    }
    _preserve_graph = True

    async def setup(self):
        self._prep_output_dir("output.ndjson")
        self.siem_friendly = self.config.get("siem_friendly", False)
        return True

    async def handle_event(self, event):
        event_json = dict(event)
        if self.siem_friendly:
            event_json["data"] = {event.type: event_json.pop("data", "")}
        event_str = json.dumps(event_json)
        if self.file is not None:
            self.file.write(event_str + "\n")
            self.file.flush()
        if self.config.get("console", False) or "human" not in self.scan.modules:
            self.stdout(event_str)

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if self._file is not None:
            self.info(f"Saved JSON output to {self.output_file}")
