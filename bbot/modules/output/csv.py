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
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / "output.csv"
        self.helpers.mkdir(self.output_file.parent)
        self._file = None
        self._writer = None
        return True

    @property
    def writer(self):
        if self._writer is None:
            self._writer = csv.writer(self.file)
            self._writer.writerow(["Event type", "Event data", "Source Module", "Scope Distance", "Event Tags"])
        return self._writer

    @property
    def file(self):
        if self._file is None:
            self._file = open(self.output_file, mode="a", newline="")
        return self._file

    def writerow(self, row):
        self.writer.writerow(row)
        self.file.flush()

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
        if self._file is not None:
            with suppress(Exception):
                self.file.close()
