import csv
from .csv import CSV

from bbot.core.helpers.misc import make_ip_type, is_ip, is_port

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
        self.custom_fields = {}
        self.open_port_producers = "httpx" in self.scan.modules or any(
            ["portscan" in m.flags for m in self.scan.modules.values()]
        )
        self.use_previous = self.config.get("use_previous", False)
        self.emitted_contents = False
        ret = super().setup()
        return ret

    def handle_event(self, event):
        if (
            (not event._internal)
            and str(event.module) != "speculate"
            and event.type in self.watched_events
            and self.scan.in_scope(event)
            and not "unresolved" in event.tags
        ):
            ip_key = _make_hostkey(event.host, event.resolved_hosts)
            if ip_key not in self.assets:
                self.assets[ip_key] = Asset(event.host)
            self.assets[ip_key].absorb_event(event)

    def report(self):
        for asset in sorted(self.assets.values(), key=lambda a: str(a.host)):
            findings_and_vulns = asset.findings.union(asset.vulnerabilities)
            ports = getattr(asset, "ports", set())
            ports = [str(p) for p in sorted([int(p) for p in asset.ports])]
            ips = sorted([str(i) for i in getattr(asset, "ip_addresses", [])])
            hostkey = _make_hostkey(asset.host, ips)
            row = {
                "Host": getattr(asset, "host", ""),
                "Provider": getattr(asset, "provider", ""),
                "IP(s)": ",".join(ips),
                "Status": "Active" if asset.ports else "N/A",
                "Open Ports": ",".join(ports),
                "Risk Rating": severity_map[getattr(asset, "risk_rating", "")],
                "Findings": "\n".join(findings_and_vulns),
                "Description": "\n".join(str(x) for x in getattr(asset, "technologies", set())),
            }
            custom_fields = self.custom_fields.get(hostkey, None)
            if custom_fields is not None:
                row.update(custom_fields)
            row.update(asset.custom_fields)
            self.writerow(row)

        if self._file is not None:
            self.info(f"Saved asset-inventory output to {self.output_file}")

    def emit_contents(self):
        if self.use_previous and not self.emitted_contents:
            self.emitted_contents = True
            if self.output_file.is_file():
                self.info(f"Emitting previous results from {self.output_file}")
                with open(self.output_file, newline="") as f:
                    c = csv.DictReader(f)
                    for row in c:
                        host = row.get("Host", "").strip()
                        if not host:
                            continue
                        host = make_ip_type(host)
                        asset = self.assets.get(host, None)
                        if asset is None:
                            asset = Asset(host)
                            self.assets[host] = asset
                        asset.absorb_csv_row(row)
                        self.add_custom_headers(list(asset.custom_fields))
                        for ip in asset.ip_addresses:
                            ip_event = self.make_event(ip, "IP_ADDRESS", source=self.scan.root_event)
                            ip_event.make_in_scope()
                            self.emit_event(ip_event)
                            for port in asset.ports:
                                netloc = self.helpers.make_netloc(ip, port)
                                open_port_event = self.make_event(netloc, "OPEN_TCP_PORT", source=ip_event)
                                open_port_event.make_in_scope()
                                self.emit_event(open_port_event)
            else:
                self.warning(
                    f"use_previous=True was set but no previous asset inventory was found at {self.output_file}"
                )

    def finish(self):
        self.emit_contents()

    def _run_hooks(self):
        """
        modules can use self.asset_inventory_hook() to add custom functionality to asset_inventory
        the asset inventory module is passed in as the first argument to the method.
        """
        if not self._ran_hooks:
            self._ran_hooks = True
            for module in self.scan.modules.values():
                hook = getattr(module, "asset_inventory_hook", None)
                if hook is not None and callable(hook):
                    hook(self)


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
        self.custom_fields = {}

    def absorb_csv_row(self, row):
        # ips
        ip_addresses = [i.strip() for i in row.get("IP(s)", "").split(",")]
        ips = [make_ip_type(i) for i in ip_addresses if i and is_ip(i)]
        self.ip_addresses = set([i for i in ips if is_ip(i)])
        # ports
        ports = [i.strip() for i in row.get("Open Ports", "").split(",")]
        self.ports.update(set(i for i in ports if i and is_port(i)))
        # findings
        findings = [i.strip() for i in row.get("Findings", "").splitlines()]
        self.findings.update(set(i for i in findings if i))
        # technologies
        technologies = [i.strip() for i in row.get("Description", "").splitlines()]
        self.technologies.update(set(i for i in technologies if i))
        # risk rating
        risk_rating = row.get("Risk Rating", "").strip()
        if risk_rating and risk_rating.isdigit() and int(risk_rating) > self.risk_rating:
            self.risk_rating = int(risk_rating)
        # provider
        provider = row.get("Provider", "").strip()
        if provider:
            self.provider = provider
        # custom fields
        for k, v in row.items():
            v = str(v)
            # update the custom field if it doesn't clash with our main fields
            # and if the new value isn't blank
            if v and k not in asset_inventory.header_row:
                self.custom_fields[k] = v

    def absorb_event(self, event):
        if not is_ip(event.host):
            self.host = event.host

        self.ip_addresses = set(i for i in event.resolved_hosts if is_ip(i))

        if event.port:
            self.ports.add(str(event.port))

        if event.type == "FINDING":
            location = event.data.get("url", event.data.get("host", ""))
            if location:
                self.findings.add(f"{location}:{event.data['description']}")

        if event.type == "VULNERABILITY":
            location = event.data.get("url", event.data.get("host", ""))
            if location:
                self.findings.add(f"{location}:{event.data['description']}:{event.data['severity']}")
                severity_int = severity_map.get(event.data.get("severity", "N/A"), 0)
                if severity_int > self.risk_rating:
                    self.risk_rating = severity_int

        if event.type == "TECHNOLOGY":
            self.technologies.add(event.data["technology"])

        for tag in event.tags:
            if tag.startswith("cdn-") or tag.startswith("cloud-"):
                self.provider = tag
                break

    @property
    def ip_key(self):
        return _make_hostkey(self.host, self.ip_addresses)


def _make_hostkey(host, ips):
    """
    We handle public and private IPs differently
    If the IPs are public, we dedupe by host
    If they're private, we dedupe by the IPs themselves
    """
    if isinstance(ips, str):
        ips = ips.split(",")
    ips = [make_ip_type(i) for i in ips]
    is_private = ips and all(is_ip(i) and i.is_private for i in ips)
    if is_private:
        return ",".join(sorted([str(i) for i in ips]))
    return str(host)
