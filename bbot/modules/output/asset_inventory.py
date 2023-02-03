from .csv import CSV

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

    header_row = ["Host", "IP(s)", "Status", "Open Ports", "Risk Rating", "Findings", "Description"]
    filename = "asset-inventory.csv"

    def setup(self):
        self.assets = {}
        self.open_port_producers = "httpx" in self.scan.modules or any(
            ["portscan" in m.flags for m in self.scan.modules.values()]
        )
        return super().setup()

    def handle_event(self, event):
        if (
            (not event._internal)
            and str(event.module) != "speculate"
            and event.type in self.watched_events
            and self.scan.in_scope(event)
            and not "unresolved" in event.tags
        ):
            if event.host not in self.assets:
                self.assets[event.host] = Asset(event.host)

            for rh in event.resolved_hosts:
                if self.helpers.is_ip(rh):
                    self.assets[event.host].ip_addresses.add(str(rh))

            if event.port:
                self.assets[event.host].ports.add(str(event.port))

            if event.type == "FINDING":
                location = event.data.get("url", event.data.get("host"))
                self.assets[event.host].findings.add(f"{location}:{event.data['description']}")

            if event.type == "VULNERABILITY":
                location = event.data.get("url", event.data.get("host"))
                self.assets[event.host].findings.add(
                    f"{location}:{event.data['description']}:{event.data['severity']}"
                )
                severity_int = severity_map.get(event.data.get("severity", "N/A"), 0)
                if severity_int > self.assets[event.host].risk_rating:
                    self.assets[event.host].risk_rating = severity_int

            if event.type == "TECHNOLOGY":
                self.assets[event.host].technologies.add(event.data["technology"])

    def report(self):
        for asset in sorted(self.assets.values(), key=lambda a: str(a.host)):
            findings_and_vulns = asset.findings.union(asset.vulnerabilities)
            self.writerow(
                [
                    getattr(asset, "host", ""),
                    ",".join(str(x) for x in getattr(asset, "ip_addresses", set())),
                    "Active" if (asset.ports) else ("Inactive" if self.open_port_producers else "N/A"),
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
