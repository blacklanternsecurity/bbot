import json
import functools
import subprocess
from contextlib import suppress

from bbot.modules.base import BaseModule


class masscan(BaseModule):
    flags = ["active", "portscan", "aggressive"]
    watched_events = ["SCAN"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {"description": "Port scan IP subnets with masscan"}
    # 600 packets/s ~= entire private IP space in 8 hours
    options = {"ports": "80,443", "rate": 600, "wait": 10, "ping_first": False, "use_cache": False}
    options_desc = {
        "ports": "Ports to scan",
        "rate": "Rate in packets per second",
        "wait": "Seconds to wait for replies after scan is complete",
        "ping_first": "Only portscan hosts that reply to pings",
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
    _qsize = 100

    def setup(self):
        self.ports = self.config.get("ports", "80,443")
        self.rate = self.config.get("rate", 600)
        self.wait = self.config.get("wait", 10)
        self.ping_first = self.config.get("ping_first", False)
        self.alive_hosts = dict()
        # make a quick dry run to validate ports etc.
        self._target_findkey = "9.8.7.6"
        if not self.helpers.in_tests:
            try:
                dry_run_command = self._build_masscan_command(self._target_findkey, dry_run=True)
                dry_run_result = self.helpers.run(dry_run_command)
                self.masscan_config = dry_run_result.stdout
                self.masscan_config = "\n".join(l for l in self.masscan_config.splitlines() if "nocapture" not in l)
            except subprocess.CalledProcessError as e:
                self.warning(f"Error in masscan: {e.stderr}")
                return False

        self.run_time = self.helpers.make_date()
        self.use_cache = self.config.get("use_cache", False)
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
        return True

    def handle_event(self, event):
        if self.use_cache:
            self.emit_from_cache()
        else:
            exclude, invalid_exclude = self._build_targets(self.scan.blacklist)
            targets, invalid_targets = self._build_targets(self.scan.whitelist)
            if invalid_exclude > 0:
                self.warning(
                    f"Masscan can only accept IP addresses or IP ranges for blacklist ({invalid_exclude:,} blacklisted were hostnames)"
                )
            if invalid_targets > 0:
                self.warning(
                    f"Masscan can only accept IP addresses or IP ranges as target ({invalid_targets:,} targets were hostnames)"
                )

            if not targets:
                self.warning("No targets specified")
                return

            # ping scan
            if self.ping_first:
                self.verbose("Starting masscan (ping scan)")

                self.masscan(targets, result_callback=self.append_alive_host, exclude=exclude, ping=True)
                targets = ",".join(str(h) for h in self.alive_hosts)
                if not targets:
                    self.warning("No hosts responded to pings")
                    return

            # TCP SYN scan
            if self.ports:
                self.verbose("Starting masscan (TCP SYN scan)")
                self.masscan(targets, result_callback=self.emit_open_tcp_port, exclude=exclude)
            else:
                self.verbose("No ports specified, skipping TCP SYN scan")
            # save memory
            self.alive_hosts.clear()

    def masscan(self, targets, result_callback, exclude=None, ping=False):
        # config file
        masscan_config = self.masscan_config.replace(self._target_findkey, targets)
        self.debug("Masscan config:")
        for line in masscan_config.splitlines():
            self.debug(line)
        config_file = self.helpers.tempfile(masscan_config)
        # output file
        process_output = functools.partial(self.process_output, result_callback=result_callback)
        json_output_file = self.helpers.tempfile_tail(process_output)
        # command
        command = self._build_masscan_command(config=config_file, exclude=exclude, ping=ping)
        command += ("-oJ", json_output_file)
        # execute
        self.helpers.run(command, sudo=True)

    def _build_masscan_command(self, targets=None, config=None, exclude=None, dry_run=False, ping=False):
        command = ("masscan", "--rate", self.rate, "--wait", self.wait, "--open-only")
        if targets is not None:
            command += (targets,)
        if config is not None:
            command += ("-c", config)
        if ping:
            command += ("--ping",)
        elif not dry_run:
            command += ("-p", self.ports)
        if exclude is not None:
            command += ("--exclude", exclude)
        if dry_run:
            command += ("--echo",)
        return command

    def process_output(self, line, result_callback):
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
                result += f":{port_number}"
                if source is None:
                    source = self.make_event(ip, "IP_ADDRESS", source=self.get_source_event(ip))
                    self.emit_event(source)
            result_callback(result, source=source)

    def append_alive_host(self, host, source):
        host_event = self.make_event(host, "IP_ADDRESS", source=self.get_source_event(host))
        self.alive_hosts[host] = host_event
        self._write_ping_result(host)
        self.emit_event(host_event)

    def emit_open_tcp_port(self, data, source):
        self._write_syn_result(data)
        self.emit_event(data, "OPEN_TCP_PORT", source=source)

    def emit_from_cache(self):
        ip_events = {}
        # ping scan
        if self.ping_cache.is_file():
            cached_pings = list(self.helpers.read_file(self.ping_cache))
            if cached_pings:
                self.success(f"{len(cached_pings):,} hosts loaded from previous ping scan")
            else:
                self.verbose(f"No hosts cached from previous ping scan")
            for ip in cached_pings:
                ip_event = self.make_event(ip, "IP_ADDRESS", source=self.get_source_event(ip))
                ip_events[ip] = ip_event
                self.emit_event(ip_event)
        # syn scan
        if self.syn_cache.is_file():
            cached_syns = list(self.helpers.read_file(self.syn_cache))
            if cached_syns:
                self.success(f"{len(cached_syns):,} hosts loaded from previous SYN scan")
            else:
                self.warning(f"No hosts cached from previous SYN scan")
            for line in cached_syns:
                host, port = self.helpers.split_host_port(line)
                host = str(host)
                source_event = ip_events.get(host)
                if source_event is None:
                    self.verbose(f"Source event not found for {line}")
                    source_event = self.make_event(line, "IP_ADDRESS", source=self.get_source_event(line))
                    self.emit_event(source_event)
                self.emit_event(line, "OPEN_TCP_PORT", source=source_event)

    def get_source_event(self, host):
        source_event = self.scan.whitelist.get(host)
        if source_event is None:
            source_event = self.scan.root_event
        return source_event

    def _build_targets(self, target):
        invalid_targets = 0
        targets = []
        for t in target:
            t = self.helpers.make_ip_type(t.data)
            if isinstance(t, str):
                invalid_targets += 1
            else:
                targets.append(t)
        return ",".join(str(t) for t in targets), invalid_targets

    def cleanup(self):
        if self.ping_first:
            with suppress(Exception):
                self.ping_cache_fd.close()
        with suppress(Exception):
            self.syn_cache_fd.close()

    def _write_ping_result(self, host):
        if self.ping_cache_fd is None:
            self.helpers.backup_file(self.ping_cache)
            self.ping_cache_fd = open(self.ping_cache, "w")
        self.ping_cache_fd.write(f"{host}\n")

    def _write_syn_result(self, data):
        if self.syn_cache_fd is None:
            self.helpers.backup_file(self.syn_cache)
            self.syn_cache_fd = open(self.syn_cache, "w")
        self.syn_cache_fd.write(f"{data}\n")
