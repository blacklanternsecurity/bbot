import csv
from pathlib import Path
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class CSV(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to CSV"}
    options = {"output_file": ""}
    options_desc = {"output_file": "Output to CSV file"}
    emit_graph_trail = False

    def setup(self):
        self.output_file = self.config.get("output_file", "")
        self.file = None
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / "output.csv"
        self.helpers.mkdir(self.output_file.parent)
        self.file = open(self.output_file, mode="w", newline="")
        self.writer = csv.writer(self.file)
        self.writerow(["Event type", "Event data", "Source Module", "Scope Distance", "Event Tags"])
        return True

    def writerow(self, row):
        self.writer.writerow(row)
        if self.output_file and self.file is not None:
            self.file.flush()
        elif not self.output_file:
            self.stdout(self.file.read().strip())

    def handle_event(self, event):
        self.writerow(
            [
                getattr(event, "type", ""),
                getattr(event, "data", ""),
                str(getattr(event, "module", "")),
                str(getattr(event, "scope_distance", "")),
                ",".join(sorted(list(getattr(event, "tags", [])))),
            ]
        )

    def cleanup(self):
        if self.output_file and self.file is not None:
            with suppress(Exception):
                self.file.close()
