import json
import subprocess
from bbot.modules.base import BaseModule


class naabu(BaseModule):
    watched_events = ["IP_ADDRESS", "DNS_NAME", "IP_RANGE"]
    produced_events = ["OPEN_TCP_PORT"]
    flags = ["active", "portscan", "aggressive"]
    meta = {"description": "Execute port scans with naabu"}
    options = {
        "ports": "",
        "top_ports": 100,
        "version": "2.1.1",
    }
    options_desc = {
        "ports": "ports to scan",
        "top_ports": "top ports to scan",
        "version": "naabu version",
    }
    max_event_handlers = 2
    batch_size = 100
    _priority = 2

    deps_ansible = [
        {
            "name": "install libpcap (Debian)",
            "package": {"name": "libpcap0.8", "state": "present"},
            "become": True,
            "when": """ansible_facts['os_family'] == 'Debian'""",
            "ignore_errors": True,
        },
        {
            "name": "install libpcap (others)",
            "package": {"name": "libpcap", "state": "present"},
            "become": True,
            "when": """ansible_facts['os_family'] != 'Debian'""",
            "ignore_errors": True,
        },
        {
            "name": "symlink libpcap",
            "file": {"src": "/usr/lib/libpcap.so", "dest": "#{BBOT_LIB}/libpcap.so.0.8", "state": "link"},
            "when": """ansible_facts['os_family'] != 'Debian'""",
            "ignore_errors": True,
        },
        {
            "name": "Download naabu",
            "unarchive": {
                "src": "https://github.com/projectdiscovery/naabu/releases/download/v#{BBOT_MODULES_NAABU_VERSION}/naabu_#{BBOT_MODULES_NAABU_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH}.zip",
                "include": "naabu",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        },
    ]

    def setup(self):
        self.helpers.depsinstaller.ensure_root(message="Naabu requires root privileges")
        return True

    def handle_batch(self, *events):
        _input = [str(e.data) for e in events]
        command = self.construct_command()
        for line in self.helpers.run_live(command, input=_input, stderr=subprocess.DEVNULL, sudo=True):
            try:
                j = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing line "{line}" as JSON: {e}')
                break
            host = j.get("host", j.get("ip"))
            port = j.get("port")

            source_event = None
            # check exact matches first
            for event in events:
                if host == str(event.host):
                    source_event = event
                    break
            # then make a broader check, for cidrs etc.
            if source_event is None:
                intermediary_event = None
                for event in events:
                    if host in event:
                        intermediary_event = event
                        break
                if intermediary_event is not None:
                    source_event = self.make_event(host, "IP_ADDRESS", source=intermediary_event)
                    if source_event:
                        self.emit_event(source_event)

            if source_event is None:
                self.warning(f'Failed to correlate source event for host "{host}"')
                continue

            self.emit_event(f"{host}:{port}", "OPEN_TCP_PORT", source=source_event)

    def construct_command(self):
        ports = self.config.get("ports", "")
        top_ports = self.config.get("top_ports", "")
        command = [
            "naabu",
            "-silent",
            "-json",
            # "-r",
            # self.helpers.resolver_file
        ]
        if ports:
            command += ["-p", ports]
        else:
            command += ["-top-ports", top_ports]
        return command

    def cleanup(self):
        resume_file = self.helpers.current_dir / "resume.cfg"
        resume_file.unlink(missing_ok=True)
