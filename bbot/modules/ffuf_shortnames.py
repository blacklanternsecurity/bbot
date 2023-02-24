import re
import random
import string

from bbot.modules.deadly.ffuf import ffuf


class ffuf_shortnames(ffuf):
    watched_events = ["URL_HINT"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["brute-force", "aggressive", "active", "web-advanced", "iis-shortnames"]
    meta = {"description": "Use ffuf in combination IIS shortnames"}

    options = {
        "wordlist": "",  # default is defined within setup function
        "wordlist_extensions": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-extensions-lowercase.txt",
        "lines": 1000000,
        "max_depth": 1,
        "version": "1.5.0",
        "extensions": "",
        "ignore_redirects": True,
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "wordlist_extensions": "Specify wordlist to use when making extension lists",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "max_depth": "the maxium directory depth to attempt to solve",
        "version": "ffuf version",
        "extensions": "Optionally include a list of extensions to extend the keyword with (comma separated)",
        "ignore_redirects": "Explicitly ignore redirects (301,302)",
    }

    in_scope_only = True

    deps_ansible = [
        {
            "name": "Download ffuf",
            "unarchive": {
                "src": "https://github.com/ffuf/ffuf/releases/download/v#{BBOT_MODULES_FFUF_VERSION}/ffuf_#{BBOT_MODULES_FFUF_VERSION}_#{BBOT_OS_PLATFORM}_#{BBOT_CPU_ARCH}.tar.gz",
                "include": "ffuf",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    def setup(self):
        self.sanity_canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist = self.config.get("wordlist", "")
        if not wordlist:
            wordlist = f"{self.helpers.wordlist_dir}/ffuf_shortname_candidates.txt"
        self.wordlist = self.helpers.wordlist(wordlist)
        wordlist_extensions = self.config.get("wordlist_extensions", "")
        self.wordlist_extensions = self.helpers.wordlist(wordlist_extensions)
        self.extensions = self.config.get("extensions")
        self.ignore_redirects = self.config.get("ignore_redirects")
        return True

    def handle_event(self, event):
        filename_hint = re.sub(r"~\d", "", event.parsed.path.rsplit(".", 1)[0].split("/")[-1]).lower()

        if len(filename_hint) == 6:
            tempfile, tempfile_len = self.generate_templist(self.wordlist, prefix=filename_hint)
            self.verbose(
                f"generated temp word list of size [{str(tempfile_len)}] for filename hint: [{filename_hint}]"
            )
        else:
            tempfile = self.helpers.tempfile([filename_hint], pipe=False)
            tempfile_len = 1

        if tempfile_len > 0:
            root_stub = "/".join(event.parsed.path.split("/")[:-1])
            root_url = f"{event.parsed.scheme}://{event.parsed.netloc}{root_stub}/"

            if "shortname-file" in event.tags:
                used_extensions = []
                extension_hint = event.parsed.path.rsplit(".", 1)[1].lower().strip()

                with open(self.wordlist_extensions) as f:
                    for l in f:
                        l = l.lower().lstrip(".")
                        if l.lower().startswith(extension_hint):
                            used_extensions.append(l.strip())

                for ext in used_extensions:
                    for r in self.execute_ffuf(tempfile, event, root_url, suffix=f".{ext}"):
                        self.emit_event(r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"])

            elif "shortname-directory" in event.tags:
                for r in self.execute_ffuf(tempfile, event, root_url):
                    self.emit_event(r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"])
