import json
import subprocess

from .base import BaseModule


class dnsx(BaseModule):

    watched_events = ["DOMAIN"]
    produced_events = ["SUBDOMAIN"]
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
    }
    options_desc = {"wordlist": "Subdomain wordlist URL"}
    max_threads = 5
    batch_size = 10
    subdomain_file = None

    def setup(self):

        self.subdomain_file = self.helpers.download(
            self.config.get("wordlist"), cache_hrs=720
        )
        if not self.subdomain_file:
            self.error("Failed to download wordlist")
            self.set_error_state()

    def handle_batch(self, *events):

        command = [
            "dnsx",
            "-silent",
            "-json",
            "-d",
            ",".join([str(e.data) for e in events]),
            "-w",
            self.subdomain_file,
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
