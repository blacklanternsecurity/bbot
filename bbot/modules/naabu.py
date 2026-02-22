import json
import ipaddress
import subprocess
from contextlib import suppress

from radixtarget import RadixTarget, host_size_key

from bbot.modules.base import BaseModule


class naabu(BaseModule):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS", "IP_RANGE", "DNS_NAME"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {
        "description": "Port scan with naabu (ProjectDiscovery). By default, scans top 100 ports.",
        "created_date": "2026-02-19",
        "author": "GitHub Copilot",
    }

    options = {
        "version": "2.4.0",
        "top_ports": 100,
        "ports": "",
        "rate": 1000,
        "threads": 25,
        # 'c' (connect) works without root; 's' (syn) generally requires root
        "scan_type": "c",
        "retries": 3,
        "timeout_ms": 1000,
        "exclude_cdn": False,
        "scan_all_ips": False,
        "module_timeout": 259200,  # 3 days
    }
    options_desc = {
        "version": "naabu version",
        "top_ports": "Top ports to scan (default 100) (to override, specify 'ports')",
        "ports": "Ports to scan (naabu -p format, e.g. '80,443,100-200')",
        "rate": "Packets to send per second (naabu -rate)",
        "threads": "General internal worker threads (naabu -c)",
        "scan_type": "Type of port scan: 'c' (connect) or 's' (syn)",
        "retries": "Number of retries for the port scan",
        "timeout_ms": "Timeout in milliseconds to wait before timing out",
        "exclude_cdn": "Skip full port scans for CDN/WAF (only scan 80,443)",
        "scan_all_ips": "Scan all IPs associated with a hostname (naabu -sa)",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }

    deps_ansible = [
        {
            "name": "Download naabu",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/naabu/releases/download/v#{BBOT_MODULES_NAABU_VERSION}/naabu_#{BBOT_MODULES_NAABU_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH_GOLANG}.zip",
                "include": "naabu",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    batch_size = 1000000
    _shuffle_incoming_queue = False

    async def setup(self):
        self.top_ports = int(self.config.get("top_ports", 100))
        self.rate = int(self.config.get("rate", 1000))
        self.threads = int(self.config.get("threads", 25))
        self.scan_type = str(self.config.get("scan_type", "c")).lower().strip() or "c"
        self.retries = int(self.config.get("retries", 3))
        self.timeout_ms = int(self.config.get("timeout_ms", 1000))
        self.exclude_cdn = bool(self.config.get("exclude_cdn", False))
        self.scan_all_ips = bool(self.config.get("scan_all_ips", False))

        self.ports = self.config.get("ports", "")
        if self.ports:
            try:
                self.helpers.parse_port_string(self.ports)
            except ValueError as e:
                return False, f"Error parsing ports '{self.ports}': {e}"

        if self.scan_type not in ("c", "s", "connect", "syn"):
            return False, f"Invalid scan_type '{self.scan_type}' (expected 'c' or 's')"

        # naabu runs CONNECT scans without root; SYN scans generally require root
        if self.scan_type in ("s", "syn"):
            self.helpers.depsinstaller.ensure_root(message="naabu SYN scans require root privileges")

        # keeps track of individual scanned IPs and their open ports (to avoid rescanning)
        self.open_port_cache = {}
        # keeps track of which IPs/subnets have already been scanned
        self.scanned = self.helpers.make_target(acl_mode=True)

        self.prep_blacklist()
        return True

    async def handle_batch(self, *events):
        targets, correlator = await self.make_targets(events, self.scanned)
        if not targets:
            return

        target_file = self.helpers.tempfile(targets, pipe=False)
        try:
            command = self._build_naabu_command(target_file)
            use_sudo = self.scan_type in ("s", "syn")
            async for line in self.run_process_live(command, sudo=use_sudo, stderr=subprocess.DEVNULL):
                for ip, port in self.parse_json_line(line):
                    parent_events = correlator.search(ip)
                    if parent_events is None:
                        self.debug(f"Failed to correlate {ip} to targets")
                        continue
                    emitted_hosts = set()
                    for parent_event in parent_events:
                        if parent_event.type == "DNS_NAME":
                            host = parent_event.host
                        else:
                            host = ip
                        if host not in emitted_hosts:
                            await self.emit_open_port(host, port, parent_event)
                            emitted_hosts.add(host)
        finally:
            target_file.unlink(missing_ok=True)

    async def make_targets(self, events, scanned_tracker):
        """Convert events into a list of targets, skipping ones that have already been scanned."""
        correlator = RadixTarget()
        targets = set()
        for event in sorted(events, key=lambda e: host_size_key(e.host)):
            if not event.host:
                continue

            ips = set()
            try:
                ips.add(ipaddress.ip_network(event.host, strict=False))
            except Exception:
                for h in event.resolved_hosts:
                    with suppress(Exception):
                        ips.add(ipaddress.ip_network(h, strict=False))

            for ip in ips:
                # check if we already found open ports on this IP
                if event.type != "IP_RANGE":
                    ip_hash = hash(ip.network_address)
                    already_found_ports = self.open_port_cache.get(ip_hash, None)
                    if already_found_ports is not None:
                        for port in already_found_ports:
                            await self.emit_open_port(event.host, port, event)

                # build a correlation from the IP back to its original parent event
                events_set = correlator.search(ip)
                if events_set is None:
                    correlator.insert(ip, {event})
                else:
                    events_set.add(event)

                # has this IP already been scanned?
                if not scanned_tracker.get(ip):
                    scanned_tracker.add(ip)
                    targets.add(str(ip))
                else:
                    self.debug(f"Skipping {ip} because it's already been scanned")

        return targets, correlator

    async def emit_open_port(self, host, port, parent_event):
        event_data = self.helpers.make_netloc(str(host), port)
        event = self.make_event(
            event_data,
            "OPEN_TCP_PORT",
            parent=parent_event,
            context=f"{{module}} executed a naabu scan against {parent_event.data} and found: {{event.type}}: {{event.data}}",
        )
        await self.emit_event(event)
        return event

    def parse_json_line(self, line):
        try:
            j = json.loads(line)
        except Exception:
            return

        ip = j.get("ip", "")
        port = j.get("port", None)
        if not ip or port is None:
            return

        # ignore UDP results (BBOT event is OPEN_TCP_PORT)
        proto = str(j.get("protocol", "tcp")).lower()
        if proto and proto != "tcp":
            return

        try:
            port = int(port)
        except Exception:
            return

        ip = self.helpers.make_ip_type(ip)
        if not self.helpers.is_ip_type(ip, network=False):
            return

        ip_hash = hash(ip)
        try:
            self.open_port_cache[ip_hash].add(port)
        except KeyError:
            self.open_port_cache[ip_hash] = {port}

        yield ip, port

    def prep_blacklist(self):
        exclude = []
        for t in self.scan.blacklist:
            # blacklist events may be DNS_NAME, IP_ADDRESS, IP_RANGE, etc
            with suppress(Exception):
                exclude.append(str(t.data))
        if not exclude:
            # naabu requires an exclude file to exist if -exclude-file is used; keep a dummy entry
            exclude = ["255.255.255.255"]
        self.exclude_file = self.helpers.tempfile(exclude, pipe=False)

    def _build_naabu_command(self, target_file):
        scan_type = "c" if self.scan_type in ("c", "connect") else "s"
        command = [
            "naabu",
            "-silent",
            "-json",
            "-scan-type",
            scan_type,
            "-list",
            str(target_file),
            "-exclude-file",
            str(self.exclude_file),
            "-rate",
            str(self.rate),
            "-c",
            str(self.threads),
            "-retries",
            str(self.retries),
            "-timeout",
            str(self.timeout_ms),
        ]

        # prefer explicit ports over top ports
        if self.ports:
            command += ["-p", str(self.ports)]
        else:
            command += ["-top-ports", str(self.top_ports)]

        if self.exclude_cdn:
            command.append("-exclude-cdn")

        if self.scan_all_ips:
            command.append("-scan-all-ips")

        dns_resolvers = ",".join(self.helpers.system_resolvers)
        if dns_resolvers:
            command += ["-r", dns_resolvers]

        return command

    async def cleanup(self):
        with suppress(Exception):
            self.exclude_file.unlink()
