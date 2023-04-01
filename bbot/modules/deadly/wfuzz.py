from bbot.modules.base import BaseModule

import random
import string
#import json


class wfuzz(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["aggressive", "active"]
    meta = {"description": "A web fuzzer written in python"}

    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "lines": 5000,
        "max_depth": 0,
        "version": "2.0.0",
        "extensions": "",
        "ignore_redirects": True,
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "max_depth": "the maxium directory depth to attempt to solve",
        "version": "ffuf version",
        "extensions": "Optionally include a list of extensions to extend the keyword with (comma separated)",
        "ignore_redirects": "Explicitly ignore redirects (301,302)",
    }

    banned_characters = [" "]

    blacklist = ["images", "css", "image"]

    deps_ansible = [
        {
            "name": "Install pycurl dependencies (Non-Debian)",
            "package": {"name": "gcc,libcurl-devel,openssl-devel,python3-devel", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] != 'Debian' and ansible_facts['os_family'] != 'Archlinux'",
            "ignore_errors": True,
        },
        {
            "name": "Install pycurl dependencies (Debian)",
            "package": {"name": "build-essential,libcurl4-openssl-dev,libssl-dev", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Debian'",
            "ignore_errors": True,
        },
        {
            "name": "Install pycurl dependencies (Arch)",
            "package": {"name": "gcc", "state": "present"},
            "become": True,
            "when": "ansible_facts['os_family'] == 'Archlinux'",
            "ignore_errors": True,
        },
    ]

    deps_pip = ["wfuzz"]

    in_scope_only = True

    def setup(self):
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist_url = self.config.get("wordlist", "")
        self.debug(f"Using wordlist [{wordlist_url}]")
        self.wordlist = self.helpers.wordlist(wordlist_url)
        f = open(self.wordlist, "r")
        self.wordlist_lines = f.readlines()
        f.close()
        self.tempfile, tempfile_len = self.generate_templist()
        self.verbose(f"Generated dynamic wordlist with length [{str(tempfile_len)}]")
        self.extensions = self.config.get("extensions")
        self.ignore_redirects = self.config.get("ignore_redirects")
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

        exts = ["", "/"]
        if self.extensions:
            for ext in self.extensions.split(","):
                exts.append(f".{ext}")

        filters = self.baseline_wfuzz(fixed_url, exts=exts)
        for r in self.execute_wfuzz(self.tempfile, fixed_url, exts=exts, filters=filters):
            self.emit_event(r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['code']}"])

    def filter_event(self, event):
        if "endpoint" in event.tags:
            self.debug(f"rejecting URL [{event.data}] because we don't wfuzz endpoints")
            return False
        return True

    def baseline_wfuzz(self, url, exts=[""], prefix="", suffix="", mode="normal"):
        filters = {}
        for ext in exts:
            # For each "extension", we will attempt to build a baseline using 4 requests

            canary_string_4 = "".join(random.choice(string.ascii_lowercase) for i in range(4))
            canary_string_6 = "".join(random.choice(string.ascii_lowercase) for i in range(6))
            canary_string_8 = "".join(random.choice(string.ascii_lowercase) for i in range(8))
            canary_string_10 = "".join(random.choice(string.ascii_lowercase) for i in range(10))
            canary_temp_file = self.helpers.tempfile(
                [canary_string_4, canary_string_6, canary_string_8, canary_string_10], pipe=False
            )
            canary_results = []

            for canary_r in self.execute_wfuzz(
                canary_temp_file, url, prefix=prefix, suffix=suffix, mode=mode, baseline=True
            ):
                canary_results.append(canary_r)

            # First, lets check to make sure we got all 4 requests. If we didn't, there are likely serious connectivity issues.
            # We should issue a warning in that case.

            if len(canary_results) != 4:
                self.warning(
                    f"Could not attain baseline for URL [{url}] ext [{ext}] because baseline results are missing. Possible connectivity issues."
                )
                filters[ext] = "ABORT"
                continue

            # if the codes are different, we should abort, this should also be a warning, as it is highly unusual behavior
            if len(set(d["code"] for d in canary_results)) != 1:
                self.hugesuccess("Got different codes for each baseline. This could indicate load balancing")
                filters[ext] = "ABORT"
                continue

            # if the code we received was a 404, this is the one case where we can be safe not applying a filter (because 404 is already filtered out)
            if canary_results[0]["code"] == 404:
                self.debug("All baseline results were 404, we don't need any filters")
                filters[ext] = None
                continue

            # we start by seeing if all of the baselines have the same character count
            if len(set(d["chars"] for d in canary_results)) == 1:
                self.debug("All baseline results had the same char count, we can make a filter on that")
                filters[ext] = f"c!={str(canary_results[0]['code'])} or h!={str(canary_results[0]['chars'])}"
                continue

            # if that doesn't work we can try words
            if len(set(d["words"] for d in canary_results)) == 1:
                self.debug("All baseline results had the same word count, we can make a filter on that")
                filters[ext] = f"c!={str(canary_results[0]['code'])} or w!={str(canary_results[0]['words'])}"
                continue

            # as a last resort we will try lines
            if len(set(d["lines"] for d in canary_results)) == 1:
                self.debug("All baseline results had the same word count, we can make a filter on that")
                filters[ext] = f"c!={str(canary_results[0]['code'])} or l!={str(canary_results[0]['lines'])}"
                continue

            # if even the line count isn't stable, we can only reliably count on the result if the code is different
            filters[ext] = f"c!={str(canary_results[0]['code'])}"

        return filters

    def execute_wfuzz(self, tempfile, url, prefix="", suffix="", exts=[""], filters={}, mode="normal", baseline=False):
        for ext in exts:
            if mode == "normal":
                self.debug("in mode [normal]")

                fuzz_url = f"{url}{prefix}FUZZ{suffix}"
                command = [
                    "wfuzz",
                    "-H",
                    f"User-Agent: {self.scan.useragent}",
                    "-o",
                    "json",
                    "-w",
                    tempfile,
                    "-u",
                    f"{fuzz_url}{ext}",
                ]

            elif mode == "hostheader":
                self.debug("in mode [hostheader]")

                command = [
                    "wfuzz",
                    "-H",
                    f"User-Agent: {self.scan.useragent}",
                    "-H",
                    f"Host: FUZZ{suffix}",
                    "-o",
                    "json",
                    "-w",
                    tempfile,
                    "-u",
                    f"{url}",
                ]
            else:
                self.debug("invalid mode specified, aborting")
                return

            if not baseline:
                command.append("--hc")
                command.append("404")

                if ext in filters.keys():
                    if filters[ext] == "ABORT":
                        self.warning(
                            "Exiting from wfuzz run early, received an ABORT filter. This probably means the page was too dynamic for a baseline."
                        )
                        continue

                    elif filters[ext] == None:
                        pass

                    else:
                        command.append("--filter")
                        command.append(filters[ext])

            for jsonstring in self.helpers.run_live(command):
                self.critical(jsonstring)
                # if len(jsonstring) > 0:
                #     jsondata = json.loads(jsonstring)
                # else:
                #     self.debug("Received no data from wfuzz")
                #     return

                # if any(self.canary in d.get("payload", "") for d in jsondata):
                #     self.verbose(f"Found 'abort' string in results for command: [{' '.join(str(x) for x in command)}]")
                #     break

                # for i in jsondata:
                #     yield i

    def generate_templist(self, prefix=None):
        line_count = 0

        virtual_file = []
        for idx, val in enumerate(self.wordlist_lines):
            if idx > self.config.get("lines"):
                break
            if len(val) > 0:
                if val.strip().lower() in self.blacklist:
                    self.debug(f"Skipping adding [{val.strip()}] to wordlist because it was in the blacklist")
                else:
                    if not prefix or val.strip().lower().startswith(prefix.strip().lower()):
                        if not any(char in val.strip().lower() for char in self.banned_characters):
                            line_count += 1
                            virtual_file.append(f"{val.strip().lower()}")
        virtual_file.append(self.canary)
        return self.helpers.tempfile(virtual_file, pipe=False), line_count
