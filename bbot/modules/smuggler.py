import sys

from bbot.modules.base import BaseModule


"""
wrapper for https://github.com/defparam/smuggler.git
"""


class smuggler(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "web-advanced", "slow", "brute-force"]
    meta = {"description": "Check for HTTP smuggling"}

    in_scope_only = True

    deps_ansible = [
        {
            "name": "Get smuggler repo",
            "git": {"repo": "https://github.com/defparam/smuggler.git", "dest": "#{BBOT_TOOLS}/smuggler"},
        }
    ]

    def setup(self):
        self.scanned_hosts = set()
        return True

    def handle_event(self, event):
        host = f"{event.parsed.scheme}://{event.parsed.netloc}/"
        host_hash = hash(host)
        if host_hash in self.scanned_hosts:
            self.debug(f"Host {host} was already scanned, exiting")
            return
        else:
            self.scanned_hosts.add(host_hash)

        command = [
            sys.executable,
            f"{self.scan.helpers.tools_dir}/smuggler/smuggler.py",
            "--no-color",
            "-q",
            "-u",
            event.data,
        ]
        for f in self.helpers.run_live(command):
            if "Issue Found" in f:
                technique = f.split(":")[0].rstrip()
                text = f.split(":")[1].split("-")[0].strip()
                description = f"[HTTP SMUGGLER] [{text}] Technique: {technique}"
                self.emit_event(
                    {"host": str(event.host), "url": event.data, "description": description}, "FINDING", source=event
                )
