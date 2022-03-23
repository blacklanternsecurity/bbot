import json
import subprocess

from .base import BaseModule


class dnsx(BaseModule):

    watched_events = ["DOMAIN"]
    produced_events = ["SUBDOMAIN"]
    max_threads = 5
    batch_size = 10

    def handle_batch(self, *events):

        subdomains = ["www", "mail"]
        command = [
            "dnsx",
            "-silent",
            "-json",
            "-d",
            ",".join([str(e) for e in events]),
            "-w",
            ",".join(subdomains),
        ]
        self.debug(" ".join(command))
        proc = subprocess.run(
            command, text=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE
        )
        for line in proc.stdout.splitlines():
            j = json.loads(line)
            host = j.get("host", "")
            if host:
                source_event = None
                for event in events:
                    if host in event:
                        source_event = event
                        break

                self.emit_event(host, "SUBDOMAIN", source_event)
