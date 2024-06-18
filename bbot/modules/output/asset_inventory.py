import csv
import ipaddress
from contextlib import suppress

from .csv import CSV
from bbot.core.helpers.misc import make_ip_type, is_ip, is_port, best_http_status

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
    watched_events = [
        "OPEN_TCP_PORT",
        "DNS_NAME",
        "URL",
        "FINDING",
        "VULNERABILITY",
        "TECHNOLOGY",
        "IP_ADDRESS",
        "WAF",
        "HTTP_RESPONSE",
    ]
    produced_events = ["IP_ADDRESS", "OPEN_TCP_PORT"]
    meta = {
        "description": "Merge hosts, open ports, technologies, findings, etc. into a single asset inventory CSV",
        "created_date": "2022-09-30",
        "author": "@liquidsec",
    }
    options = {"output_file": "", "use_previous": False, "recheck": False, "summary_netmask": 16}
    options_desc = {
        "output_file": "Set a custom output file",
        "use_previous": "Emit previous asset inventory as new events (use in conjunction with -n <old_scan_name>)",
        "recheck": "When use_previous=True, don't retain past details like open ports or findings. Instead, allow them to be rediscovered by the new scan",
        "summary_netmask": "Subnet mask to use when summarizing IP addresses at end of scan",
    }

    header_row = [
        "Host",
        "Provider",
        "IP (External)",
        "IP (Internal)",
        "Open Ports",
        "HTTP Status",
        "HTTP Title",
        "Risk Rating",
        "Findings",
        "Technologies",
        "WAF",
        "DNS Records",
    ]
    filename = "asset-inventory.csv"

    async def setup(self):
        self.assets = {}
        self.use_previous = self.config.get("use_previous", False)
        self.recheck = self.config.get("recheck", False)
        self.summary_netmask = self.config.get("summary_netmask", 16)
        self.emitted_contents = False
        self._ran_hooks = False
        ret = await super().setup()
        return ret

    async def filter_event(self, event):
        if event._internal:
            return False, "event is internal"
        if event.type not in self.watched_events:
            return False, "event type is not in watched_events"
        if not self.scan.in_scope(event):
            return False, "event is not in scope"
        if "unresolved" in event.tags:
            return False, "event is unresolved"
        return True, ""

    async def handle_event(self, event):
        if (await self.filter_event(event))[0]:
            hostkey = _make_hostkey(event.host, event.resolved_hosts)
            if hostkey not in self.assets:
                self.assets[hostkey] = Asset(event.host, self.recheck)
            self.assets[hostkey].absorb_event(event)

    async def report(self):
        stats = dict()
        totals = dict()

        def increment_stat(stat, value):
            try:
                totals[stat] += 1
            except KeyError:
                totals[stat] = 1
            if not stat in stats:
                stats[stat] = {}
            try:
                stats[stat][value] += 1
            except KeyError:
                stats[stat][value] = 1

        def sort_key(asset):
            host = str(asset.host)
            is_digit = False
            with suppress(IndexError):
                is_digit = host[0].isdigit()
            return (is_digit, host)

        for asset in sorted(self.assets.values(), key=sort_key):
            findings_and_vulns = asset.findings.union(asset.vulnerabilities)
            ports = getattr(asset, "ports", set())
            ports = [str(p) for p in sorted([int(p) for p in asset.ports])]
            ips_all = getattr(asset, "ip_addresses", [])
            ips_external = sorted([str(ip) for ip in [i for i in ips_all if not i.is_private]])
            ips_internal = sorted([str(ip) for ip in [i for i in ips_all if i.is_private]])
            host = self.helpers.make_ip_type(getattr(asset, "host", ""))
            if host and isinstance(host, str):
                _, domain = self.helpers.split_domain(host)
                if domain:
                    increment_stat("Domains", domain)
            for ip in ips_all:
                net = ipaddress.ip_network(f"{ip}/{self.summary_netmask}", strict=False)
                increment_stat("IP Addresses", str(net))
            for port in ports:
                increment_stat("Open Ports", port)
            row = {
                "Host": host,
                "Provider": getattr(asset, "provider", ""),
                "IP (External)": ", ".join(ips_external),
                "IP (Internal)": ", ".join(ips_internal),
                "Open Ports": ", ".join(ports),
                "HTTP Status": asset.http_status_full,
                "HTTP Title": str(getattr(asset, "http_title", "")),
                "Risk Rating": severity_map[getattr(asset, "risk_rating", "")],
                "Findings": "\n".join(findings_and_vulns),
                "Technologies": "\n".join(str(x) for x in getattr(asset, "technologies", set())),
                "WAF": getattr(asset, "waf", ""),
                "DNS Records": ", ".join(sorted([str(r) for r in getattr(asset, "dns_records", [])])),
            }
            row.update(asset.custom_fields)
            self.writerow(row)

        for header in ("Domains", "IP Addresses", "Open Ports"):
            table_header = [header, ""]
            if header in stats:
                table = []
                stats_sorted = sorted(stats[header].items(), key=lambda x: x[-1], reverse=True)
                total = totals[header]
                for k, v in stats_sorted:
                    table.append([str(k), f"{v:,}/{total} ({v/total*100:.1f}%)"])
                self.log_table(table, table_header, table_name=f"asset-inventory-{header}")

        if self._file is not None:
            self.info(f"Saved asset-inventory output to {self.output_file}")

    async def finish(self):
        if self.use_previous and not self.emitted_contents:
            self.emitted_contents = True
            if self.output_file.is_file():
                self.info(f"Emitting previous results from {self.output_file}")
                with open(self.output_file, newline="") as f:
                    c = csv.DictReader(f)
                    for row in c:
                        # yield to event loop to make sure we don't hold up the scan
                        await self.helpers.sleep(0)
                        host = row.get("Host", "").strip()
                        ips = row.get("IP (External)", "") + "," + row.get("IP (Internal)", "")
                        if not host or not ips:
                            continue
                        hostkey = _make_hostkey(host, ips)
                        asset = self.assets.get(hostkey, None)
                        if asset is None:
                            asset = Asset(host, self.recheck)
                            self.assets[hostkey] = asset
                        asset.absorb_csv_row(row)
                        self.add_custom_headers(list(asset.custom_fields))
                        if not is_ip(asset.host):
                            host_event = self.make_event(
                                asset.host, "DNS_NAME", parent=self.scan.root_event, raise_error=True
                            )
                            await self.emit_event(
                                host_event, context="{module} emitted previous result: {event.type}: {event.data}"
                            )
                            for port in asset.ports:
                                netloc = self.helpers.make_netloc(asset.host, port)
                                open_port_event = self.make_event(netloc, "OPEN_TCP_PORT", parent=host_event)
                                if open_port_event:
                                    await self.emit_event(
                                        open_port_event,
                                        context="{module} emitted previous result: {event.type}: {event.data}",
                                    )
                        else:
                            for ip in asset.ip_addresses:
                                ip_event = self.make_event(
                                    ip, "IP_ADDRESS", parent=self.scan.root_event, raise_error=True
                                )
                                await self.emit_event(
                                    ip_event, context="{module} emitted previous result: {event.type}: {event.data}"
                                )
                                for port in asset.ports:
                                    netloc = self.helpers.make_netloc(ip, port)
                                    open_port_event = self.make_event(netloc, "OPEN_TCP_PORT", parent=ip_event)
                                    if open_port_event:
                                        await self.emit_event(
                                            open_port_event,
                                            context="{module} emitted previous result: {event.type}: {event.data}",
                                        )
            else:
                self.warning(
                    f"use_previous=True was set but no previous asset inventory was found at {self.output_file}"
                )
        else:
            self._run_hooks()

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
    def __init__(self, host, recheck):
        self.host = host
        self.ip_addresses = set()
        self.dns_records = set()
        self.ports = set()
        self.findings = set()
        self.vulnerabilities = set()
        self.status = "UNKNOWN"
        self.risk_rating = 0
        self.provider = ""
        self.waf = ""
        self.technologies = set()
        self.custom_fields = {}
        self.http_status = 0
        self.http_title = ""
        self.redirect_location = ""
        self.recheck = recheck

    def absorb_csv_row(self, row):
        # host
        host = make_ip_type(row.get("Host", "").strip())
        if host and not is_ip(host):
            self.host = host
        # ips
        self.ip_addresses = set(_make_ip_list(row.get("IP (External)", "")))
        self.ip_addresses.update(set(_make_ip_list(row.get("IP (Internal)", ""))))
        # If user reqests a recheck dont import the following fields to force them to be rechecked
        if not self.recheck:
            # ports
            ports = [i.strip() for i in row.get("Open Ports", "").split(",")]
            self.ports.update(set(i for i in ports if i and is_port(i)))
            # findings
            findings = [i.strip() for i in row.get("Findings", "").splitlines()]
            self.findings.update(set(i for i in findings if i))
            # technologies
            technologies = [i.strip() for i in row.get("Technologies", "").splitlines()]
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

        dns_children = getattr(event, "_dns_children", {})
        for rdtype, records in sorted(dns_children.items(), key=lambda x: x[0]):
            for record in sorted([str(r) for r in records]):
                self.dns_records.add(f"{rdtype}:{record}")

        http_status = getattr(event, "http_status", 0)
        update_http_status = bool(http_status) and best_http_status(http_status, self.http_status) == http_status
        if update_http_status:
            self.http_status = http_status
            if str(http_status).startswith("3"):
                if event.type == "HTTP_RESPONSE":
                    redirect_location = getattr(event, "redirect_location", "")
                    if redirect_location:
                        self.redirect_location = redirect_location
            else:
                self.redirect_location = ""

        if event.resolved_hosts:
            self.ip_addresses.update(set(_make_ip_list(event.resolved_hosts)))

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

        if event.type == "WAF":
            if waf := event.data.get("waf", ""):
                if update_http_status or not self.waf:
                    self.waf = waf

        if event.type == "HTTP_RESPONSE":
            if title := event.data.get("title", ""):
                if update_http_status or not self.http_title:
                    self.http_title = title

        for tag in event.tags:
            if tag.startswith("cdn-") or tag.startswith("cloud-"):
                self.provider = tag
                break

    @property
    def hostkey(self):
        return _make_hostkey(self.host, self.ip_addresses)

    @property
    def http_status_full(self):
        return str(self.http_status) + (f" -> {self.redirect_location}" if self.redirect_location else "")


def _make_hostkey(host, ips):
    """
    We handle public and private IPs differently
    If the IPs are public, we dedupe by host
    If they're private, we dedupe by the IPs themselves
    """
    ips = _make_ip_list(ips)
    is_private = ips and all(is_ip(i) and i.is_private for i in ips)
    if is_private:
        return ",".join(sorted([str(i) for i in ips]))
    return str(host)


def _make_ip_list(ips):
    if isinstance(ips, str):
        ips = [i.strip() for i in ips.split(",")]
    ips = [make_ip_type(i) for i in ips if i and is_ip(i)]
    return ips
