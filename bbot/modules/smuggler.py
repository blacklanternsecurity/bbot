import sys

from bbot.modules.base import BaseModule


"""
wrapper for https://github.com/defparam/smuggler.git
"""


class smuggler(BaseModule):
    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "slow", "web-thorough"]
    meta = {"description": "Check for HTTP smuggling"}

    in_scope_only = True
    per_host_only = True

    deps_ansible = [
        {
            "name": "Get smuggler repo",
            "git": {"repo": "https://github.com/defparam/smuggler.git", "dest": "#{BBOT_TOOLS}/smuggler"},
        }
    ]

    async def handle_event(self, event):
        command = [
            sys.executable,
            f"{self.scan.helpers.tools_dir}/smuggler/smuggler.py",
            "--no-color",
            "-q",
            "-u",
            event.data,
        ]
        async for line in self.helpers.run_live(command):
            for f in line.split("\r"):
                if "Issue Found" in f:
                    technique = f.split(":")[0].rstrip()
                    text = f.split(":")[1].split("-")[0].strip()
                    description = f"[HTTP SMUGGLER] [{text}] Technique: {technique}"
                    self.emit_event(
                        {"host": str(event.host), "url": event.data, "description": description},
                        "FINDING",
                        source=event,
                    )
