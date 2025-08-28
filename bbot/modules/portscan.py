import json
import ipaddress
from contextlib import suppress
from radixtarget import RadixTarget, host_size_key

from bbot.modules.base import BaseModule


# TODO: this module is getting big. It should probably be two modules: one for ping and one for SYN.


class portscan(BaseModule):
    flags = ["active", "portscan", "safe"]
    watched_events = ["IP_ADDRESS", "IP_RANGE", "DNS_NAME"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {
        "description": "Port scan with masscan. By default, scans top 100 ports.",
        "created_date": "2024-05-15",
        "author": "@TheTechromancer",
    }
    options = {
        "top_ports": 100,
        "ports": "",
        # ping scan at 600 packets/s ~= private IP space in 8 hours
        "rate": 300,
        "wait": 5,
        "ping_first": False,
        "ping_only": False,
        "adapter": "",
        "adapter_ip": "",
        "adapter_mac": "",
        "router_mac": "",
        "module_timeout": 259200,  # 3 days
    }
    options_desc = {
        "top_ports": "Top ports to scan (default 100) (to override, specify 'ports')",
        "ports": "Ports to scan",
        "rate": "Rate in packets per second",
        "wait": "Seconds to wait for replies after scan is complete",
        "ping_first": "Only portscan hosts that reply to pings",
        "ping_only": "Ping sweep only, no portscan",
        "adapter": 'Manually specify a network interface, such as "eth0" or "tun0". If not specified, the first network interface found with a default gateway will be used.',
        "adapter_ip": "Send packets using this IP address. Not needed unless masscan's autodetection fails",
        "adapter_mac": "Send packets using this as the source MAC address. Not needed unless masscan's autodetection fails",
        "router_mac": "Send packets to this MAC address as the destination. Not needed unless masscan's autodetection fails",
        "module_timeout": "Max time in seconds to spend handling each batch of events",
    }
    deps_common = ["masscan"]
    batch_size = 1000000
    _shuffle_incoming_queue = False

    async def setup(self):
        self.top_ports = self.config.get("top_ports", 100)
        self.rate = self.config.get("rate", 300)
        self.wait = self.config.get("wait", 10)
        self.ping_first = self.config.get("ping_first", False)
        self.ping_only = self.config.get("ping_only", False)
        self.ping_scan = self.ping_first or self.ping_only
        self.adapter = self.config.get("adapter", "")
        self.adapter_ip = self.config.get("adapter_ip", "")
        self.adapter_mac = self.config.get("adapter_mac", "")
        self.router_mac = self.config.get("router_mac", "")
        self.ports = self.config.get("ports", "")
        if self.ports:
            try:
                self.helpers.parse_port_string(self.ports)
            except ValueError as e:
                return False, f"Error parsing ports '{self.ports}': {e}"

        # keeps track of individual scanned IPs and their open ports
        # this is necessary because we may encounter more hosts with the same IP
        # and we want to avoid scanning them again
        self.open_port_cache = {}
        # keeps track of which IPs/subnets have already been scanned
        self.syn_scanned = self.helpers.make_target(acl_mode=True)
        self.ping_scanned = self.helpers.make_target(acl_mode=True)
        self.prep_blacklist()
        self.helpers.depsinstaller.ensure_root(message="Masscan requires root privileges")
        # check if we're set up for IPv6
        self.ipv6_support = True
        dry_run_command = self._build_masscan_command(target_file=self.helpers.tempfile(["::1"], pipe=False), wait=0)
        ipv6_result = await self.run_process(
            dry_run_command,
            sudo=True,
            _log_stderr=False,
        )
        if ipv6_result is None:
            return False, "Masscan failed to run"
        returncode = getattr(ipv6_result, "returncode", 0)
        if returncode and "failed to detect IPv6 address" in ipv6_result.stderr:
            self.warning("It looks like you are not set up for IPv6. IPv6 targets will not be scanned.")
            self.ipv6_support = False
        return True

    async def handle_batch(self, *events):
        # ping scan
        if self.ping_scan:
            ping_targets, ping_correlator = await self.make_targets(events, self.ping_scanned)
            ping_events = []
            async for alive_host, _, parent_event in self.masscan(ping_targets, ping_correlator, ping=True):
                # port 0 means icmp ping response
                ping_event = await self.emit_open_port(alive_host, 0, parent_event)
                ping_events.append(ping_event)
            syn_targets, syn_correlator = await self.make_targets(ping_events, self.syn_scanned)
        else:
            syn_targets, syn_correlator = await self.make_targets(events, self.syn_scanned)

        # TCP SYN scan
        if not self.ping_only:
            async for ip, port, parent_event in self.masscan(syn_targets, syn_correlator):
                await self.emit_open_port(ip, port, parent_event)
        else:
            self.debug("Only ping sweep was requested, skipping TCP SYN scan")

    async def masscan(self, targets, correlator, ping=False):
        scan_type = "ping" if ping else "SYN"
        self.debug(f"Starting masscan {scan_type} scan")
        if not targets:
            self.debug("No targets specified, aborting.")
            return

        target_file = self.helpers.tempfile(targets, pipe=False)
        command = self._build_masscan_command(target_file, ping=ping)
        stats_file = self.helpers.tempfile_tail(callback=self.log_masscan_status)
        try:
            with open(stats_file, "w") as stats_fh:
                async for line in self.run_process_live(command, sudo=True, stderr=stats_fh):
                    for ip, port in self.parse_json_line(line):
                        parent_events = correlator.search(ip)
                        # masscan gets the occasional junk result. this is harmless and
                        # seems to be a side effect of it having its own TCP stack
                        # see https://github.com/robertdavidgraham/masscan/issues/397
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
                                yield host, port, parent_event
                                emitted_hosts.add(host)
        finally:
            for file in (stats_file, target_file):
                file.unlink(missing_ok=True)

    async def make_targets(self, events, scanned_tracker):
        """
        Convert events into a list of targets, skipping ones that have already been scanned
        """
        correlator = RadixTarget()
        targets = set()
        for event in sorted(events, key=lambda e: host_size_key(e.host)):
            # skip events without host
            if not event.host:
                continue
            ips = set()
            try:
                # first assume it's an ip address / ip range
                ips.add(ipaddress.ip_network(event.host, strict=False))
            except Exception:
                # if it's a hostname, get its IPs from resolved_hosts
                for h in event.resolved_hosts:
                    try:
                        ips.add(ipaddress.ip_network(h, strict=False))
                    except Exception:
                        continue

            for ip in ips:
                # remove IPv6 addresses if we're not scanning IPv6
                if not self.ipv6_support and ip.version == 6:
                    self.debug(f"Not scanning IPv6 address {ip} because we aren't set up for IPv6")
                    continue

                # check if we already found open ports on this IP
                if event.type != "IP_RANGE":
                    ip_hash = hash(ip.network_address)
                    already_found_ports = self.open_port_cache.get(ip_hash, None)
                    if already_found_ports is not None:
                        # if so, emit them
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
                    # if not, add it to targets!
                    scanned_tracker.add(ip)
                    targets.add(ip)
                else:
                    self.debug(f"Skipping {ip} because it's already been scanned")

        return targets, correlator

    async def emit_open_port(self, ip, port, parent_event):
        parent_is_dns_name = parent_event.type == "DNS_NAME"
        if parent_is_dns_name:
            host = parent_event.host
        else:
            host = ip

        if port == 0:
            event_data = host
            event_type = "DNS_NAME" if parent_is_dns_name else "IP_ADDRESS"
            scan_type = "ping"
        else:
            event_data = self.helpers.make_netloc(host, port)
            event_type = "OPEN_TCP_PORT"
            scan_type = "TCP SYN"

        event = self.make_event(
            event_data,
            event_type,
            parent=parent_event,
            context=f"{{module}} executed a {scan_type} scan against {parent_event.data} and found: {{event.type}}: {{event.data}}",
        )

        await self.emit_event(event)
        return event

    def parse_json_line(self, line):
        try:
            j = json.loads(line)
        except Exception:
            return
        ip = j.get("ip", "")
        if not ip:
            return
        ip = self.helpers.make_ip_type(ip)
        ip_hash = hash(ip)
        ports = j.get("ports", [])
        if not ports:
            return
        for p in ports:
            proto = p.get("proto", "")
            port_number = p.get("port", 0)
            try:
                self.open_port_cache[ip_hash].add(port_number)
            except KeyError:
                self.open_port_cache[ip_hash] = {port_number}
            if proto == "" or port_number == "":
                continue
            yield ip, port_number

    def prep_blacklist(self):
        exclude = []
        for t in self.scan.blacklist:
            t = self.helpers.make_ip_type(t.data)
            if not isinstance(t, str):
                if self.helpers.is_ip(t):
                    exclude.append(str(ipaddress.ip_network(t)))
                else:
                    exclude.append(str(t))
        if not exclude:
            exclude = ["255.255.255.255/32"]
        self.exclude_file = self.helpers.tempfile(exclude, pipe=False)

    def _build_masscan_command(self, target_file=None, ping=False, dry_run=False, wait=None):
        if wait is None:
            wait = self.wait
        command = (
            "masscan",
            "--excludefile",
            str(self.exclude_file),
            "--rate",
            self.rate,
            "--wait",
            wait,
            "--open-only",
            "-oJ",
            "-",
        )
        if target_file is not None:
            command += ("-iL", str(target_file))
        if dry_run:
            command += ("-p1", "--wait", "0")
        else:
            if self.adapter:
                command += ("--adapter", self.adapter)
            if self.adapter_ip:
                command += ("--adapter-ip", self.adapter_ip)
            if self.adapter_mac:
                command += ("--adapter-mac", self.adapter_mac)
            if self.router_mac:
                command += ("--router-mac", self.router_mac)
            if ping:
                command += ("--ping",)
            else:
                if self.ports:
                    command += ("-p", self.ports)
                else:
                    command += ("-p", self.helpers.top_tcp_ports(self.top_ports, as_string=True))
        return command

    def log_masscan_status(self, s):
        if "FAIL" in s:
            self.warning(s)
            self.warning(
                'Masscan failed to detect interface. Recommend passing "adapter_ip", "adapter_mac", and "router_mac" config options to portscan module.'
            )
        else:
            self.verbose(s)

    async def cleanup(self):
        with suppress(Exception):
            self.exclude_file.unlink()
