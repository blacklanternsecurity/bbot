import random
import string
import json
import base64

from bbot.modules.base import BaseModule


class ffuf(BaseModule):

    watched_events = ["URL"]
    produced_events = ["URL"]
    flags = ["brute-force", "aggressive", "active", "web"]
    meta = {"description": "A fast web fuzzer written in Go"}

    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "lines": 5000,
        "max_depth": 0,
        "version": "1.5.0",
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "max_depth": "the maxium directory depth to attempt to solve",
        "version": "ffuf version",
    }

    blacklist = ["images", "css", "image"]

    deps_ansible = [
        {
            "name": "Download ffuf",
            "unarchive": {
                "src": "https://github.com/ffuf/ffuf/releases/download/v{BBOT_MODULES_FFUF_VERSION}/ffuf_{BBOT_MODULES_FFUF_VERSION}_linux_amd64.tar.gz",
                "include": "ffuf",
                "dest": "{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    in_scope_only = True

    def setup(self):

        self.sanity_canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist_url = self.config.get("wordlist", "")
        self.wordlist = self.helpers.wordlist(wordlist_url)
        self.tempfile = self.generate_templist(self.wordlist)
        return True

    def handle_event(self, event):
        if self.helpers.url_depth(event.data) > self.config.get("max_depth"):
            self.debug(f"Exceeded max depth, aborting event")
            return

        # only FFUF against a directory
        if "." in event.parsed.path.split("/")[-1]:
            self.debug("Aborting FFUF as period was detected in right-most path segment (likely a file)")
            return
        else:
            # if we think its a directory, normalize it.
            fixed_url = event.data.rstrip("/") + "/"

        for r in self.execute_ffuf(self.tempfile, event, fixed_url):
            self.emit_event(r["url"], "URL", source=event, tags=[f"status-{r['status']}"])

    def execute_ffuf(self, tempfile, event, url, suffix=""):

        fuzz_url = f"{url}FUZZ{suffix}"
        command = ["ffuf", "-ac", "-json", "-w", tempfile, "-u", fuzz_url]
        for found in self.helpers.run_live(command):
            try:
                found_json = json.loads(found)
                input_json = found_json.get("input", {})
                if type(input_json) != dict:
                    self.debug("Error decoding JSON from ffuf")
                    continue
                encoded_input = input_json.get("FUZZ", "")
                input_val = base64.b64decode(encoded_input).decode()
                if len(input_val.rstrip()) > 0:
                    if self.scan.stopping:
                        break
                    if input_val.rstrip() == self.sanity_canary:
                        self.debug("Found sanity canary! aborting remainder of run to avoid junk data...")
                        return
                    else:
                        yield found_json

            except json.decoder.JSONDecodeError:
                self.debug("Received invalid JSON from FFUF")

    def generate_templist(self, wordlist, prefix=None):

        f = open(wordlist, "r")
        fl = f.readlines()
        f.close()

        virtual_file = []
        virtual_file.append(self.sanity_canary)
        for idx, val in enumerate(fl):
            if idx > self.config.get("lines"):
                break
            if len(val) > 0:

                if val.strip().lower() in self.blacklist:
                    self.debug(f"Skipping adding [{val.strip()}] to wordlist because it was in the blacklist")
                else:
                    if not prefix or val.startswith(prefix):
                        virtual_file.append(f"{val.strip()}")
        return self.helpers.tempfile(virtual_file, pipe=False)
