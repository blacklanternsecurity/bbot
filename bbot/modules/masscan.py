import json
import functools
import subprocess

from bbot.modules.base import BaseModule


class masscan(BaseModule):

    flags = ["active", "portscan", "aggressive"]
    watched_events = ["IP_RANGE"]
    produced_events = ["OPEN_TCP_PORT"]
    meta = {"description": "Port scan IP subnets with massdns"}
    options = {"ports": "80,443", "rate": 600, "wait": 10}
    options_desc = {
        "ports": "Ports to scan",
        "rate": "Rate in packets per second",
        "wait": "Seconds to wait for replies after scan is complete",
    }
    subdomain_file = None
    deps_ansible = [
        {"name": "install dev tools", "package": {"name": ["gcc", "git", "make"], "state": "present"}, "become": True},
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
        # make a quick dry run to validate ports etc.
        try:
            dummy_event = self.make_event("127.0.0.1", "IP_ADDRESS", source=self.scan.root_event)
            self.masscan(dummy_event, dry_run=True)
        except subprocess.CalledProcessError as e:
            self.warning(f"Error in masscan: {e.stderr}")
            return False
        self.helpers.depsinstaller.ensure_root(message="Masscan requires root privileges")
        return True

    def handle_event(self, event):
        self.masscan(event)

    def masscan(self, event, dry_run=False):
        process_output = functools.partial(self.process_output, source=event)
        tempfile = self.helpers.tempfile_tail(process_output)
        command = (
            "masscan",
            event.data,
            "-p",
            self.ports,
            "--rate",
            self.rate,
            "--wait",
            self.wait,
            "--open-only",
            "-oJ",
            tempfile,
        )
        if dry_run:
            command += ("--echo",)

        result = self.helpers.run(command, sudo=not dry_run, check=dry_run)
        if dry_run:
            for line in result.stdout.splitlines():
                self.debug(line)

    def process_output(self, line, source):
        try:
            j = json.loads(line)
            ip = j.get("ip", "")
            if ip:
                ports = j.get("ports", [])
                if ports:
                    for p in ports:
                        port_number = p.get("port", "")
                        if port_number:
                            self.emit_event(f"{ip}:{port_number}", "OPEN_TCP_PORT", source=source)
        except Exception:
            return
