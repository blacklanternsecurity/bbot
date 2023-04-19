import csv
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
    watched_events = ["OPEN_TCP_PORT", "DNS_NAME", "URL", "FINDING", "VULNERABILITY", "TECHNOLOGY", "IP_ADDRESS"]
    produced_events = ["IP_ADDRESS", "OPEN_TCP_PORT"]
    meta = {"description": "Output to an asset inventory style flattened CSV file"}
    options = {"output_file": "", "use_previous": False}
    options_desc = {
        "output_file": "Set a custom output file",
        "use_previous": "Emit previous asset inventory as new events (use in conjunction with -n <old_scan_name>)",
    }

    header_row = ["Host", "Provider", "IP(s)", "Status", "Open Ports", "Risk Rating", "Findings", "Description"]
    filename = "asset-inventory.csv"

    def setup(self):
        self.assets = {}
        self.open_port_producers = "httpx" in self.scan.modules or any(
            ["portscan" in m.flags for m in self.scan.modules.values()]
        )
        self.use_previous = self.config.get("use_previous", False)
        self.emitted_contents = False
        ret = super().setup()
        if self.output_file.is_file():
            self.helpers.backup_file(self.output_file)
        return ret

    def handle_event(self, event):
        self.emit_contents()
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

            for tag in event.tags:
                if tag.startswith("cdn-") or tag.startswith("cloud-"):
                    self.assets[event.host].provider = tag
                    break

    def report(self):
        for asset in sorted(self.assets.values(), key=lambda a: str(a.host)):
            findings_and_vulns = asset.findings.union(asset.vulnerabilities)
            self.writerow(
                [
                    getattr(asset, "host", ""),
                    getattr(asset, "provider", ""),
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

    def emit_contents(self):
        if self.use_previous and not self.emitted_contents:
            self.emitted_contents = True
            if self.output_file.is_file():
                with open(self.output_file, newline="") as f:
                    c = csv.DictReader(f)
                    for line in c:
                        ips = [i.strip() for i in line.get("IP(s)", "").split(",")]
                        ips = [i for i in ips if self.helpers.is_ip(i)]
                        ports = [p.strip() for p in line.get("Open Ports", "").split(",")]
                        ports = [p for p in ports if p.isdigit() and 0 < int(p) < 65536]
                        for ip in ips:
                            ip_event = self.make_event(ip, "IP_ADDRESS", source=self.scan.root_event)
                            ip_event.make_in_scope()
                            self.emit_event(ip_event)
                            for port in ports:
                                netloc = self.helpers.make_netloc(ip, port)
                                open_port_event = self.make_event(netloc, "OPEN_TCP_PORT", source=ip_event)
                                open_port_event.make_in_scope()
                                self.emit_event(open_port_event)


class Asset:
    def __init__(self, host):
        self.host = host
        self.ip_addresses = set()
        self.ports = set()
        self.findings = set()
        self.vulnerabilities = set()
        self.status = "UNKNOWN"
        self.risk_rating = 0
        self.provider = ""
        self.technologies = set()
