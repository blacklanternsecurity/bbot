import json
import subprocess

from .base import BaseModule
from bbot.core.errors import ValidationError


class dnsx(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
    }
    options_desc = {"wordlist": "Subdomain wordlist URL"}
    max_threads = 5
    batch_size = 10
    subdomain_file = None
    target_only = True
    flags = ["brute_force"]

    def setup(self):

        self.subdomain_file = self.helpers.download(
            self.config.get("wordlist", self.options.get("wordlist")), cache_hrs=720
        )
        if not self.subdomain_file:
            self.error("Failed to download wordlist")
            return False
        return True

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
        for line in self.helpers.run_live(command, stderr=subprocess.DEVNULL):
            j = json.loads(line)
            host = j.get("host", "")
            if host:
                source_event = None
                for event in events:
                    if host in event:
                        source_event = event
                        break

                try:
                    self.emit_event(host, "DNS_NAME", source_event)
                except ValidationError as e:
                    self.debug(f"Error validating {host}: {e}")
