import json
from contextlib import suppress

from bbot.modules.templates.portscanner import portscanner


class masscan(portscanner):
    flags = ["active", "portscan", "aggressive"]
    watched_events = ["IP_ADDRESS", "IP_RANGE"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {"description": "Port scan with masscan. By default, scans top 100 ports."}
    options = {
        "top_ports": 100,
        "ports": "",
        # ping scan at 600 packets/s ~= entire private IP space in 8 hours
        "rate": 600,
        "wait": 5,
        "ping_first": False,
        "ping_only": False,
        "use_cache": False,
    }
    options_desc = {
        "top_ports": "Top ports to scan (default 100) (to override, specify 'ports')",
        "ports": "Ports to scan",
        "rate": "Rate in packets per second",
        "wait": "Seconds to wait for replies after scan is complete",
        "ping_first": "Only portscan hosts that reply to pings",
        "ping_only": "Ping sweep only, no portscan",
        "use_cache": "Instead of scanning, use the results from the previous scan",
    }
    deps_ansible = [
        {
            "name": "install dev tools",
            "package": {"name": ["gcc", "git", "make"], "state": "present"},
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Download masscan source code",
            "git": {
                "repo": "https://github.com/robertdavidgraham/masscan.git",
                "dest": "#{BBOT_TEMP}/masscan",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build masscan",
            "command": {
                "chdir": "#{BBOT_TEMP}/masscan",
                "cmd": "make -j",
                "creates": "#{BBOT_TEMP}/masscan/bin/masscan",
            },
        },
        {
            "name": "Install masscan",
            "copy": {"src": "#{BBOT_TEMP}/masscan/bin/masscan", "dest": "#{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]
    batch_size = 1000000

    async def setup(self):
        self.top_ports = self.config.get("top_ports", 100)
        self.rate = self.config.get("rate", 600)
        self.wait = self.config.get("wait", 10)
        self.ping_first = self.config.get("ping_first", False)
        self.ping_only = self.config.get("ping_only", False)
        self.use_cache = self.config.get("use_cache", False)
        self.ports = self.config.get("ports", "")
        if self.ports:
            try:
                self.helpers.parse_port_string(self.ports)
            except ValueError as e:
                return False, f"Error parsing ports: {e}"
        self.alive_hosts = dict()

        _, invalid_targets = self._build_targets(self.scan.target)
        if invalid_targets > 0:
            self.warning(
                f"Masscan can only accept IP addresses or IP ranges as target ({invalid_targets:,} targets were hostnames)"
            )

        self.run_time = self.helpers.make_date()
        self.ping_cache = self.scan.home / f"masscan_ping.txt"
        self.syn_cache = self.scan.home / f"masscan_syn.txt"
        if self.use_cache:
            files_exist = self.ping_cache.is_file() or self.syn_cache.is_file()
            files_empty = self.helpers.filesize(self.ping_cache) == 0 and self.helpers.filesize(self.syn_cache) == 0
            if not files_exist:
                return (
                    False,
                    f"use_cache is True but could not find cache file at {self.ping_cache} or {self.syn_cache}",
                )
            if files_empty:
                return (
                    False,
                    f"use_cache is True but could cached files {self.ping_cache} and {self.syn_cache} are empty",
                )
        else:
            self.helpers.depsinstaller.ensure_root(message="Masscan requires root privileges")
        self.ping_cache_fd = None
        self.syn_cache_fd = None

        return await super().setup()

    async def handle_batch(self, *events):
        if self.use_cache:
            await self.emit_from_cache()
        else:
            targets = [str(e.data) for e in events]
            if not targets:
                self.warning("No targets specified")
                return

            # ping scan
            if self.ping_first or self.ping_only:
                self.verbose("Starting masscan (ping scan)")

                await self.masscan(targets, result_callback=self.append_alive_host, ping=True)
                targets = ",".join(str(h) for h in self.alive_hosts)
                if not targets:
                    self.warning("No hosts responded to pings")
                    return

            # TCP SYN scan
            if not self.ping_only:
                self.verbose("Starting masscan (TCP SYN scan)")
                await self.masscan(targets, result_callback=self.emit_open_tcp_port)
            else:
                self.verbose("Only ping sweep was requested, skipping TCP SYN scan")
            # save memory
            self.alive_hosts.clear()

    async def masscan(self, targets, result_callback, ping=False):
        target_file = self.helpers.tempfile(targets, pipe=False)
        command = self._build_masscan_command(target_file, ping=ping)
        stats_file = self.helpers.tempfile_tail(callback=self.verbose)
        try:
            with open(stats_file, "w") as stats_fh:
                async for line in self.helpers.run_live(command, sudo=True, stderr=stats_fh):
                    await self.process_output(line, result_callback=result_callback)
        finally:
            for file in (stats_file, target_file):
                file.unlink()

    def _build_masscan_command(self, target_file=None, dry_run=False, ping=False):
        command = (
            "masscan",
            "--excludefile",
            str(self.exclude_file),
            "--rate",
            self.rate,
            "--wait",
            self.wait,
            "--open-only",
            "-oJ",
            "-",
        )
        if target_file is not None:
            command += ("-iL", str(target_file))
        if ping:
            command += ("--ping",)
        else:
            if self.ports:
                command += ("-p", self.ports)
            else:
                command += ("--top-ports", str(self.top_ports))
        if dry_run:
            command += ("--echo",)
        return command

    async def process_output(self, line, result_callback):
        try:
            j = json.loads(line)
        except Exception:
            return
        ip = j.get("ip", "")
        if not ip:
            return
        ports = j.get("ports", [])
        if not ports:
            return
        for p in ports:
            proto = p.get("proto", "")
            port_number = p.get("port", "")
            if proto == "" or port_number == "":
                continue
            result = str(ip)
            source = None
            with suppress(KeyError):
                source = self.alive_hosts[ip]
            if proto != "icmp":
                result = self.helpers.make_netloc(result, port_number)
                if source is None:
                    source = self.make_event(ip, "IP_ADDRESS", source=self.get_source_event(ip))
                    await self.emit_event(source)
            await result_callback(result, source=source)

    async def append_alive_host(self, host, source):
        host_event = self.make_event(host, "IP_ADDRESS", source=self.get_source_event(host))
        self.alive_hosts[host] = host_event
        self._write_ping_result(host)
        await self.emit_event(host_event)

    async def emit_open_tcp_port(self, data, source):
        self._write_syn_result(data)
        await self.emit_event(data, "OPEN_TCP_PORT", source=source)

    async def emit_from_cache(self):
        ip_events = {}
        # ping scan
        if self.ping_cache.is_file():
            cached_pings = list(self.helpers.read_file(self.ping_cache))
            if cached_pings:
                self.success(f"{len(cached_pings):,} hosts loaded from previous ping scan")
            else:
                self.verbose(f"No hosts cached from previous ping scan")
            for ip in cached_pings:
                if self.scan.stopping:
                    break
                ip_event = self.make_event(ip, "IP_ADDRESS", source=self.get_source_event(ip))
                ip_events[ip] = ip_event
                await self.emit_event(ip_event)
        # syn scan
        if self.syn_cache.is_file():
            cached_syns = list(self.helpers.read_file(self.syn_cache))
            if cached_syns:
                self.success(f"{len(cached_syns):,} hosts loaded from previous SYN scan")
            else:
                self.warning(f"No hosts cached from previous SYN scan")
            for line in cached_syns:
                if self.scan.stopping:
                    break
                host, port = self.helpers.split_host_port(line)
                host = str(host)
                source_event = ip_events.get(host)
                if source_event is None:
                    self.verbose(f"Source event not found for {line}")
                    source_event = self.make_event(line, "IP_ADDRESS", source=self.get_source_event(line))
                    await self.emit_event(source_event)
                await self.emit_event(line, "OPEN_TCP_PORT", source=source_event)

    def get_source_event(self, host):
        source_event = self.scan.whitelist.get(host)
        if source_event is None:
            source_event = self.scan.root_event
        return source_event

    async def cleanup(self):
        if self.ping_first:
            with suppress(Exception):
                self.ping_cache_fd.close()
        with suppress(Exception):
            self.syn_cache_fd.close()
        with suppress(Exception):
            self.exclude_file.unlink()

    def _write_ping_result(self, host):
        if self.ping_cache_fd is None:
            self.helpers.backup_file(self.ping_cache)
            self.ping_cache_fd = open(self.ping_cache, "w")
        self.ping_cache_fd.write(f"{host}\n")
        self.ping_cache_fd.flush()

    def _write_syn_result(self, data):
        if self.syn_cache_fd is None:
            self.helpers.backup_file(self.syn_cache)
            self.syn_cache_fd = open(self.syn_cache, "w")
        self.syn_cache_fd.write(f"{data}\n")
        self.syn_cache_fd.flush()
