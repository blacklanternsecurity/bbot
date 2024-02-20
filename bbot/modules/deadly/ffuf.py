from bbot.modules.base import BaseModule
from bbot.core.helpers.misc import parse_list_string

import random
import string
import json
import base64


class ffuf(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["aggressive", "active"]
    meta = {"description": "A fast web fuzzer written in Go"}

    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "lines": 5000,
        "max_depth": 0,
        "version": "2.0.0",
        "extensions": "",
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "max_depth": "the maximum directory depth to attempt to solve",
        "version": "ffuf version",
        "extensions": "Optionally include a list of extensions to extend the keyword with (comma separated)",
    }

    deps_ansible = [
        {
            "name": "Download ffuf",
            "unarchive": {
                "src": "https://github.com/ffuf/ffuf/releases/download/v#{BBOT_MODULES_FFUF_VERSION}/ffuf_#{BBOT_MODULES_FFUF_VERSION}_#{BBOT_OS}_#{BBOT_CPU_ARCH}.tar.gz",
                "include": "ffuf",
                "dest": "#{BBOT_TOOLS}",
                "remote_src": True,
            },
        }
    ]

    banned_characters = [" "]

    blacklist = ["images", "css", "image"]

    in_scope_only = True

    async def setup(self):
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist_url = self.config.get("wordlist", "")
        self.debug(f"Using wordlist [{wordlist_url}]")
        self.wordlist = await self.helpers.wordlist(wordlist_url)
        self.wordlist_lines = list(self.helpers.read_file(self.wordlist))
        self.tempfile, tempfile_len = self.generate_templist()
        self.verbose(f"Generated dynamic wordlist with length [{str(tempfile_len)}]")
        try:
            self.extensions = parse_list_string(self.config.get("extensions", ""))
            self.debug(f"Using custom extensions: [{','.join(self.extensions)}]")
        except ValueError as e:
            self.warning(f"Error parsing extensions: {e}")
            return False
        return True

    async def handle_event(self, event):
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
            for ext in self.extensions:
                exts.append(f".{ext}")

        filters = await self.baseline_ffuf(fixed_url, exts=exts)
        async for r in self.execute_ffuf(self.tempfile, fixed_url, exts=exts, filters=filters):
            await self.emit_event(r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"])

    async def filter_event(self, event):
        if "endpoint" in event.tags:
            self.debug(f"rejecting URL [{event.data}] because we don't ffuf endpoints")
            return False
        return True

    async def baseline_ffuf(self, url, exts=[""], prefix="", suffix="", mode="normal"):
        filters = {}
        for ext in exts:
            self.debug(f"running baseline for URL [{url}] with ext [{ext}]")
            # For each "extension", we will attempt to build a baseline using 4 requests

            canary_results = []

            canary_length = 4
            canary_list = []
            for i in range(0, 4):
                canary_list.append("".join(random.choice(string.ascii_lowercase) for i in range(canary_length)))
                canary_length += 2

            canary_temp_file = self.helpers.tempfile(canary_list, pipe=False)
            async for canary_r in self.execute_ffuf(
                canary_temp_file,
                url,
                prefix=prefix,
                suffix=suffix,
                mode=mode,
                baseline=True,
                apply_filters=False,
                filters=filters,
            ):
                canary_results.append(canary_r)

            # First, lets check to make sure we got all 4 requests. If we didn't, there are likely serious connectivity issues.
            # We should issue a warning in that case.

            if len(canary_results) != 4:
                self.warning(
                    f"Could not attain baseline for URL [{url}] ext [{ext}] because baseline results are missing. Possible connectivity issues."
                )
                filters[ext] = ["ABORT", "CONNECTIVITY_ISSUES"]
                continue

            # if the codes are different, we should abort, this should also be a warning, as it is highly unusual behavior
            if len(set(d["status"] for d in canary_results)) != 1:
                self.warning("Got different codes for each baseline. This could indicate load balancing")
                filters[ext] = ["ABORT", "BASELINE_CHANGED_CODES"]
                continue

            # if the code we received was a 404, we are just going to look for cases where we get a different code
            if canary_results[0]["status"] == 404:
                self.debug("All baseline results were 404, we can just look for anything not 404")
                filters[ext] = ["-fc", "404"]
                continue

            # if we only got 403, we might already be blocked by a WAF. Issue a warning, but it's possible all 'not founds' are given 403
            if canary_results[0]["status"] == 403:
                self.warning(
                    "All requests of the baseline received a 403 response. It is possible a WAF is actively blocking your traffic."
                )

            # if we only got 429, we are almost certainly getting blocked by a WAF or rate-limiting. Specifically with 429, we should respect them and abort the scan.
            if canary_results[0]["status"] == 429:
                self.warning(
                    f"Received code 429 (Too many requests) for URL [{url}]. A WAF or application is actively blocking requests, aborting."
                )
                filters[ext] = ["ABORT", "RECEIVED_429"]
                continue

            # we start by seeing if all of the baselines have the same character count
            if len(set(d["length"] for d in canary_results)) == 1:
                self.debug("All baseline results had the same char count, we can make a filter on that")
                filters[ext] = [
                    "-fc",
                    str(canary_results[0]["status"]),
                    "-fs",
                    str(canary_results[0]["length"]),
                    "-fmode",
                    "and",
                ]
                continue

            # if that doesn't work we can try words
            if len(set(d["words"] for d in canary_results)) == 1:
                self.debug("All baseline results had the same word count, we can make a filter on that")
                filters[ext] = [
                    "-fc",
                    str(canary_results[0]["status"]),
                    "-fw",
                    str(canary_results[0]["words"]),
                    "-fmode",
                    "and",
                ]
                continue

            # as a last resort we will try lines
            if len(set(d["lines"] for d in canary_results)) == 1:
                self.debug("All baseline results had the same word count, we can make a filter on that")
                filters[ext] = [
                    "-fc",
                    str(canary_results[0]["status"]),
                    "-fl",
                    str(canary_results[0]["lines"]),
                    "-fmode",
                    "and",
                ]
                continue

            # if even the line count isn't stable, we can only reliably count on the result if the code is different
            filters[ext] = ["-fc", f"{str(canary_results[0]['status'])}"]

        return filters

    async def execute_ffuf(
        self,
        tempfile,
        url,
        prefix="",
        suffix="",
        exts=[""],
        filters={},
        mode="normal",
        apply_filters=True,
        baseline=False,
    ):
        for ext in exts:
            if mode == "normal":
                self.debug("in mode [normal]")

                fuzz_url = f"{url}{prefix}FUZZ{suffix}"

                command = [
                    "ffuf",
                    "-noninteractive",
                    "-s",
                    "-H",
                    f"User-Agent: {self.scan.useragent}",
                    "-json",
                    "-w",
                    tempfile,
                    "-u",
                    f"{fuzz_url}{ext}",
                ]

            elif mode == "hostheader":
                self.debug("in mode [hostheader]")

                command = [
                    "ffuf",
                    "-noninteractive",
                    "-s",
                    "-H",
                    f"User-Agent: {self.scan.useragent}",
                    "-H",
                    f"Host: FUZZ{suffix}",
                    "-json",
                    "-w",
                    tempfile,
                    "-u",
                    f"{url}",
                ]
            else:
                self.debug("invalid mode specified, aborting")
                return

            if apply_filters:
                if ext in filters.keys():
                    if filters[ext][0] == ("ABORT"):
                        self.warning(f"Exiting from FFUF run early, received an ABORT filter: [{filters[ext][1]}]")
                        continue

                    elif filters[ext] == None:
                        pass

                    else:
                        command += filters[ext]
            else:
                command.append("-mc")
                command.append("all")

            for hk, hv in self.scan.config.get("http_headers", {}).items():
                command += ["-H", f"{hk}: {hv}"]

            async for found in self.helpers.run_live(command):
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
                        if input_val.rstrip() == self.canary:
                            self.debug("Found canary! aborting...")
                            return
                        else:
                            if mode == "normal":
                                # before emitting, we are going to send another baseline. This will immediately catch things like a WAF flipping blocking on us mid-scan
                                if baseline == False:
                                    pre_emit_temp_canary = [
                                        f
                                        async for f in self.execute_ffuf(
                                            self.helpers.tempfile(
                                                ["".join(random.choice(string.ascii_lowercase) for i in range(4))],
                                                pipe=False,
                                            ),
                                            url,
                                            prefix=prefix,
                                            suffix=suffix,
                                            mode=mode,
                                            exts=[ext],
                                            baseline=True,
                                            filters=filters,
                                        )
                                    ]
                                    if len(pre_emit_temp_canary) == 0:
                                        yield found_json
                                    else:
                                        self.warning(
                                            "Baseline changed mid-scan. This is probably due to a WAF turning on a block against you."
                                        )
                                        self.warning(f"Aborting the current run against [{url}]")
                                        return

                            yield found_json

                except json.decoder.JSONDecodeError:
                    self.debug("Received invalid JSON from FFUF")

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
