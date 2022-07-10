from .ffuf import ffuf
import random
import string


class ffuf_shortnames(ffuf):

    watched_events = ["URL_HINT"]
    produced_events = ["URL"]

    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt",
        "lines": 20000,
        "max_depth": 1,
        "version": "1.5.0",
    }

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

    extension_helper = {
        "asp": ["aspx"],
        "asm": ["asmx"],
        "ash": ["ashx"],
        "jsp": ["jspx"],
        "htm": ["html"],
        "sht": ["shtml"],
        "php": ["php2", "php3", "php4", "ph5"],
    }

    def setup(self):
        self.sanity_canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))

        wordlist = self.config.get("wordlist", "")
        self.wordlist = self.helpers.download(wordlist, cache_hrs=720)
        if not self.wordlist:
            self.warning(f'Failed to download wordlist from "{wordlist}"')
            return False
        return True

    def handle_event(self, event):

        filename_hint = event.parsed.path.rsplit(".", 1)[0].split("/")[-1]

        tempfile = self.generate_templist(self.wordlist, prefix=filename_hint)

        root_stub = "/".join(event.parsed.path.split("/")[:-1])
        root_url = f"{event.parsed.scheme}://{event.parsed.netloc}{root_stub}/"

        if "file" in event.tags:
            extension_hint = event.parsed.path.rsplit(".", 1)[1]
            used_extensions = []
            used_extensions.append(extension_hint)
            for ex in self.extension_helper.keys():
                if extension_hint == ex:
                    for ex2 in self.extension_helper[ex]:
                        used_extensions.append(ex2)

            for ext in used_extensions:
                for r in self.execute_ffuf(tempfile, event, root_url, suffix=f".{ext}"):
                    self.emit_event(r["url"], "URL", source=event, tags=[f"status-{r['status']}"])

        elif "dir" in event.tags:

            for r in self.execute_ffuf(tempfile, event, root_url):
                self.emit_event(r["url"], "URL", source=event, tags=[f"status-{r['status']}"])
