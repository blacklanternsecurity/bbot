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
    options = {"ports": "80,443", "rate": 600, "wait": 10, "ping_first": False}
    options_desc = {
        "ports": "Ports to scan",
        "rate": "Rate in packets per second",
        "wait": "Seconds to wait for replies after scan is complete",
        "ping_first": "Only portscan hosts that reply to pings",
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
        try:
            dry_run_command = self._build_masscan_command(self._target_findkey, dry_run=True)
            dry_run_result = self.helpers.run(dry_run_command)
            self.masscan_config = dry_run_result.stdout
            self.masscan_config = "\n".join(l for l in self.masscan_config.splitlines() if "nocapture" not in l)
        except subprocess.CalledProcessError as e:
            self.warning(f"Error in masscan: {e.stderr}")
            return False
        self.helpers.depsinstaller.ensure_root(message="Masscan requires root privileges")
        return True

    def handle_event(self, event):
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

            def append_alive_host(host, source):
                host_event = self.make_event(host, "IP_ADDRESS", source=self.scan.whitelist.get(host))
                self.alive_hosts[host] = host_event
                self.emit_event(host_event)

            self.masscan(targets, result_callback=append_alive_host, exclude=exclude, ping=True)
            targets = ",".join(str(h) for h in self.alive_hosts)
            if not targets:
                self.warning("No hosts responded to pings")
                return

        # TCP SYN scan
        self.verbose("Starting masscan (TCP SYN scan)")
        self.masscan(targets, result_callback=self.emit_open_tcp_port, exclude=exclude, event=event)
        # save memory
        self.alive_hosts.clear()

    def masscan(self, targets, result_callback, exclude=None, event=None, ping=False):
        # config file
        masscan_config = self.masscan_config.replace(self._target_findkey, targets)
        self.debug("Masscan config:")
        for line in masscan_config.splitlines():
            self.debug(line)
        config_file = self.helpers.tempfile(masscan_config)
        # output file
        process_output = functools.partial(self.process_output, source=event, result_callback=result_callback)
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

    def process_output(self, line, source, result_callback):
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
            if proto != "icmp":
                result += f":{port_number}"
            with suppress(KeyError):
                source = self.alive_hosts[ip]
            result_callback(result, source=source)

    def emit_open_tcp_port(self, data, source):
        self.emit_event(data, "OPEN_TCP_PORT", source=source)

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
