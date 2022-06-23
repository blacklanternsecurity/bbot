import csv
import json
from pathlib import Path

from .base import BaseOutputModule


class Line:
    def __init__(self):
        self._line = None

    def write(self, line):
        self._line = line

    def read(self):
        return self._line


class CSV(BaseOutputModule):
    options = {"output_file": ""}
    options_desc = {"output_file": "Output to CSV file"}

    def setup(self):
        self.output_file = self.config.get("output_file", "")
        self.file = None
        if self.output_file:
            filename = Path(self.output_file).resolve()
            filename.parent.mkdir(exist_ok=True, parents=True)
            self.file = open(str(filename), mode="w", newline="")
        else:
            self.file = Line()
        self.writer = csv.writer(self.file)
        self.writerow(["Event type", "Event data", "Source Module", "Event ID", "Event Tags", "Source Event ID"])
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
                getattr(event, "id", ""),
                json.dumps(sorted(list(getattr(event, "tags", [])))),
                getattr(event, "source_id", ""),
            ]
        )

    def cleanup(self):
        if self.output_file and self.file is not None:
            self.file.close()
