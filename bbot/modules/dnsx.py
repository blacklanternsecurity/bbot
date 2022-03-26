import json
import subprocess

from .base import BaseModule


class dnsx(BaseModule):

    watched_events = ["DOMAIN"]
    produced_events = ["SUBDOMAIN"]
    options = {
        # "wordlist": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2022_02_28.txt"
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt"
    }
    options_desc = {"wordlist": "Subdomain wordlist URL"}
    max_threads = 5
    batch_size = 10

    def handle_batch(self, *events):

        subdomain_file = self.helpers.download(
            self.config.get("wordlist"), cache_hrs=720
        )

        command = [
            "dnsx",
            "-silent",
            "-json",
            "-d",
            ",".join([str(e.data) for e in events]),
            "-w",
            subdomain_file,
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
