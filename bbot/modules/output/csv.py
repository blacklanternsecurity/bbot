import csv
from contextlib import suppress

from bbot.modules.output.base import BaseOutputModule


class CSV(BaseOutputModule):
    watched_events = ["*"]
    meta = {"description": "Output to CSV", "created_date": "2022-04-07", "author": "@TheTechromancer"}
    options = {"output_file": ""}
    options_desc = {"output_file": "Output to CSV file"}

    header_row = [
        "Event type",
        "Event data",
        "IP Address",
        "Source Module",
        "Scope Distance",
        "Event Tags",
        "Discovery Path",
    ]
    filename = "output.csv"
    accept_dupes = False

    async def setup(self):
        self.custom_headers = []
        self._headers_set = set()
        self._writer = None
        self._prep_output_dir(self.filename)
        return True

    @property
    def writer(self):
        if self._writer is None:
            self._writer = csv.DictWriter(self.file, fieldnames=self.fieldnames)
            self._writer.writeheader()
        return self._writer

    @property
    def file(self):
        if self._file is None:
            if self.output_file.is_file():
                self.helpers.backup_file(self.output_file)
            self._file = open(self.output_file, mode="a", newline="")
        return self._file

    @property
    def fieldnames(self):
        return self.header_row + list(self.custom_headers)

    def writerow(self, row):
        self.writer.writerow(row)
        self.file.flush()

    async def handle_event(self, event):
        # ["Event type", "Event data", "IP Address", "Source Module", "Scope Distance", "Event Tags"]
        discovery_path = getattr(event, "discovery_path", [])
        self.writerow(
            {
                "Event type": getattr(event, "type", ""),
                "Event data": getattr(event, "data", ""),
                "IP Address": ",".join(
                    str(x) for x in getattr(event, "resolved_hosts", set()) if self.helpers.is_ip(x)
                ),
                "Source Module": str(getattr(event, "module_sequence", "")),
                "Scope Distance": str(getattr(event, "scope_distance", "")),
                "Event Tags": ",".join(sorted(list(getattr(event, "tags", [])))),
                "Discovery Path": " --> ".join(discovery_path),
            }
        )

    async def cleanup(self):
        if getattr(self, "_file", None) is not None:
            with suppress(Exception):
                self.file.close()

    async def report(self):
        if self._file is not None:
            self.info(f"Saved CSV output to {self.output_file}")

    def add_custom_headers(self, headers):
        if isinstance(headers, str):
            headers = [headers]
        for header in headers:
            if header not in self._headers_set:
                self._headers_set.add(header)
                self.custom_headers.append(header)
