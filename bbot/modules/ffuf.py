import random
import string
from .base import BaseModule
import json
import base64


class app_ffuf(BaseModule):

    watched_events = ["URL"]
    produced_events = ["URL"]

    flags = ["brute-force", "active"]
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "lines": 5000,
        "max_depth": 1,
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
                "src": "https://github.com/ffuf/ffuf/releases/download/v${BBOT_MODULES_FFUF_VERSION}/ffuf_${BBOT_MODULES_FFUF_VERSION}_linux_amd64.tar.gz",
                "include": "ffuf",
                "dest": "${BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    in_scope_only = True

    def setup(self):

        self.sanity_canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist_url = self.config.get("wordlist", "")
        self.wordlist = self.helpers.download(wordlist_url, cache_hrs=720)
        if not self.wordlist:
            self.warning(f'Failed to download wordlist from "{wordlist_url}"')
            return False
        self.tempfile = self.generate_templist(self.wordlist)
        return True

    def handle_event(self, event):

        if self.helpers.url_depth(event.data) > self.config.get("max_depth"):
            self.debug(f"Exceeded max depth, aborting event")
            return

        # only FFUF against a directory

        if "." in event.parsed.path:
            self.debug("Aborting FFUF as no trailing slash was detected (likely a file)")
            return
        else:
            # if we think its a directory, normalize it.
            fixed_url = event.data.rstrip("/") + "/"

        for r in self.execute_ffuf(self.tempfile, event, fixed_url):
            input_val = base64.b64decode(r["input"]["FUZZ"]).decode()
            if len(input_val.rstrip()) > 0:
                if self.scan.stopping:
                    break
                if input_val.rstrip() == self.sanity_canary:
                    self.debug("Found sanity canary! aborting remainder of run to avoid junk data...")
                    return
                else:
                    self.emit_event(r["url"], "URL", source=event, tags=[f"status-{r['status']}"])

    def execute_ffuf(self, tempfile, event, url, prefix="", skip_dir_check=False):

        if len(prefix) > 0:
            url = url + prefix
        fuzz_url = f"{url}FUZZ"
        command = ["ffuf", "-ac", "-json", "-w", tempfile, "-u", fuzz_url]
        for found in self.helpers.run_live(command):
            found_json = json.loads(found)
            yield found_json

    def generate_templist(self, wordlist):

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
                    virtual_file.append(f"{val.strip()}")
        return self.helpers.tempfile(virtual_file, pipe=False)
