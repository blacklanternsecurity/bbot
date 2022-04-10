import random
import string
import os
from urllib.parse import urlparse
from .base import BaseModule


class ffuf(BaseModule):

    watched_events = ["URL"]
    produced_events = ["URL"]
    in_scope_only = True
    options = {
        "wordlist_dir": "/opt/wordlists/raft-small-directories.txt",
        "wordlist_files": "/opt/wordlists/raft-small-words.txt",
        "lines_dir": 1000,
        "lines_files": 1000,
        "max_depth": 3,
        "dirs_only": False,
        "extension_list": [
            "php",
            "jsp",
            "jspx",
            "asp",
            "aspx",
            "ashx",
            "asmx",
            "cfm",
            "js",
            "html",
            "zip",
        ],
    }

    options_desc = {
        "wordlist_dir": "Specify wordlist to use when finding directories",
        "wordlist_files": "specify wordlist to use when finding files",
        "lines_dir": "take only the first N lines from the wordlist when finding directories",
        "lines_files": "take only the first N lines from the wordlist when finding files",
        "max_depth": "the maxium directory depth to attempt to solve",
        "dirs_only": "Skip doing discovery for files with extensions",
        "extension_list": "The list of extensions to use during file discovery",
    }

    def setup(self):

        self.sanity_canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        self.extension_list = self.config.get("extension_list")
        joined_extension_list = " ".join(self.extension_list)
        self.debug(f"Loaded extension list: [{joined_extension_list}]")
        self.config_max_depth = self.config.get("max_depth")
        self.config_lines_dir = self.config.get("lines_dir")
        self.config_lines_files = self.config.get("lines_files")
        self.config_wordlist_dir = self.config.get("wordlist_dir")
        self.debug(str(os.path.exists(self.config_wordlist_dir)))
        if not os.path.exists(self.config_wordlist_dir):
            self.debug(
                f"Directory wordlist [{self.config_wordlist_dir}] does not exist, exiting module"
            )
            return False

        self.config_wordlist_files = self.config.get("wordlist_files")
        if not os.path.exists(self.config_wordlist_files):
            self.debug(
                f"Files wordlist [{self.config_wordlist_files}] does not exist, exiting module"
            )
            return False

        self.tempfile_dir = self.writeTempWordlist(
            self.config_wordlist_dir, self.config_lines_dir, self.sanity_canary
        )
        self.debug(
            f"Wrote temp DIR wordlist with {str(self.config_lines_dir)} lines to: {self.tempfile_dir}"
        )
        self.tempfile_files = self.writeTempWordlist(
            self.config_wordlist_files, self.config_lines_files, self.sanity_canary
        )
        self.debug(
            f"Wrote temp WORDS wordlist with {str(self.config_lines_files)} lines to: {self.tempfile_files}"
        )
        return True

    def cleanup(self):

        if os.path.exists(self.tempfile_dir):
            os.remove(self.tempfile_dir)
        if os.path.exists(self.tempfile_files):
            os.remove(self.tempfile_files)

    def handle_event(self, event):

        separator = ""
        if "/" != event.data[-1]:
            separator = "/"
        ffuf_url = f"{event.data}{separator}FUZZ"
        parsed = urlparse(ffuf_url)
        depth = len(parsed.path.replace("/FUZZ", "").rstrip("/").split("/")) - 1
        self.debug(f"URL depth is: {str(depth)}")
        if depth > self.config_max_depth:
            self.debug(f"Exceeded max depth, aborting event")
            return
        command = ["ffuf", "-ac", "-s", "-w", self.tempfile_dir, "-u", ffuf_url + "/"]
        for found_dir in self.helpers.run_live(command):
            if found_dir.rstrip() == self.sanity_canary:
                self.debug("Found sanity canary! aborting remainder of run to avoid junk data...")
                break
            self.emit_event(
                f"{event.data}{separator}{found_dir.rstrip()}/", "URL", source=event, tags=["dir"]
            )

        if not self.config.get("dirs_only"):
            for extension in self.extension_list:
                extension = extension.rstrip()
                ffuf_url = f"{event.data}{separator}FUZZ.{extension}"
                command = ["ffuf", "-ac", "-s", "-w", self.tempfile_files, "-u", ffuf_url]
                for found_file in self.helpers.run_live(command):
                    if found_file.rstrip() == self.sanity_canary:
                        self.debug(
                            "Found sanity canary! aborting remainder of run to avoid junk data..."
                        )
                        break
                    found_file_uri = f"{found_file.rstrip()}.{extension}"
                    self.debug(found_file_uri)
                    self.emit_event(
                        f"{event.data}{separator}{found_file_uri.rstrip()}",
                        "URL",
                        source=event,
                        tags=["uri"],
                    )

    def filter_event(self, event):

        if ("dir" in event.tags) or (("endpoint" not in event.tags) and ("uri" not in event.tags)):
            return True
        else:
            return False

    @staticmethod
    def writeTempWordlist(wordlist, num, sanity_canary):

        f = open(wordlist, "r")
        fl = f.readlines()
        f.close()

        randname = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        tempfilename = f"/tmp/{randname}"
        tempfile = open(tempfilename, "w")

        tempfile.write(f"{sanity_canary}\n")

        for idx, val in enumerate(fl):
            if idx > num:
                break
            tempfile.write(f"{val}")
        tempfile.close()
        return tempfilename
