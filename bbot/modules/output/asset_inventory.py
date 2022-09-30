import csv
from .csv import CSV
from pathlib import Path

severity_map = {
    "INFO": 0,
    0: "N/A",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
    "N/A": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class asset_inventory(CSV):
    watched_events = ["OPEN_TCP_PORT", "DNS_NAME", "URL", "FINDING", "VULNERABILITY", "TECHNOLOGY"]
    meta = {"description": "Output to an asset inventory style flattened CSV file"}
    options = {"output_file": ""}
    options_desc = {"output_file": "Set a custom output file"}

    def setup(self):

        self.assets = {}

        self.output_file = self.config.get("output_file", "")
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / "asset-inventory.csv"
        self.helpers.mkdir(self.output_file.parent)
        self._file = None
        self._writer = None
        return True

    def handle_event(self, event):

        if (
            event.type in self.watched_events
            and not event._internal
            and str(event.module) != "speculate"
            and "distance-0" in event.tags
        ):

            if event.host not in self.assets.keys():
                self.assets[event.host] = Asset(event.host)

            for rh in event.resolved_hosts:
                self.assets[event.host].ip_addresses.add(str(rh))

            if event.port:
                self.assets[event.host].ports.add(str(event.port))

            if event.type == "FINDING":
                self.assets[event.host].findings.add(f"{event.data['url']}:{event.data['description']}")

            if event.type == "VULNERABILITY":
                self.assets[event.host].findings.add(
                    f"{event.data['url']}:{event.data['description']}:{event.data['severity']}"
                )
                severity_int = severity_map[event.data["severity"]]
                if severity_int > self.assets[event.host].risk_rating:
                    self.assets[event.host].risk_rating = severity_int

            if event.type == "TECHNOLOGY":
                self.assets[event.host].technologies.add(event.data["technology"])

    @property
    def writer(self):
        if self._writer is None:
            self._writer = csv.writer(self.file)
            self._writer.writerow(["Host", "IP(s)", "Status", "Open Ports", "Risk Rating", "Findings", "Description"])
        return self._writer

    def report(self):
        for asset in self.assets.values():
            findings_and_vulns = asset.findings.union(asset.vulnerabilities)
            self.writerow(
                [
                    getattr(asset, "host", ""),
                    ",".join(str(x) for x in getattr(asset, "ip_addresses", set())),
                    "Active" if (asset.ports) else "Timeout",
                    ",".join(str(x) for x in getattr(asset, "ports", set())),
                    severity_map[getattr(asset, "risk_rating", "")],
                    ",".join(findings_and_vulns),
                    ",".join(str(x) for x in getattr(asset, "technologies", set())),
                ]
            )

        if self._file is not None:
            self.info(f"Saved asset-inventory output to {self.output_file}")


class Asset:
    def __init__(self, host):
        self.host = host
        self.ip_addresses = set()
        self.ports = set()
        self.findings = set()
        self.vulnerabilities = set()
        self.status = "UNKNOWN"
        self.risk_rating = 0
        self.technologies = set()
