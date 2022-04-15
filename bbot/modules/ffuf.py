import random
import string
import os
from urllib.parse import urlparse
from .base import BaseModule


class ffuf(BaseModule):

    watched_events = ["URL", "URL_HINT"]
    produced_events = ["URL"]
    in_scope_only = True

    flags = ["brute_force"]
    options = {
        "wordlist_dir": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
        "wordlist_files": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt",
        "lines_dir": 1000,
        "lines_files": 1000,
        "max_depth": 3,
        "prefix_busting": False,
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
        "prefix_busting": "Enable searching file URLs for prefix and ffufing with the prefix",
    }

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
        self.extension_list = self.config.get("extension_list")
        joined_extension_list = " ".join(self.extension_list)
        self.debug(f"Loaded extension list: [{joined_extension_list}]")
        self.config_max_depth = self.config.get("max_depth")
        self.config_lines_dir = self.config.get("lines_dir")
        self.config_lines_files = self.config.get("lines_files")
        self.config_wordlist_dir = self.helpers.download(
            self.config.get("wordlist_dir"), cache_hrs=720
        )
        if not self.config_wordlist_dir:
            f"Directory wordlist [{self.config_wordlist_dir}] did not load, exiting module"
            return False

        self.config_wordlist_files = self.helpers.download(
            self.config.get("wordlist_files"), cache_hrs=720
        )
        if not self.config_wordlist_files:
            f"Files wordlist [{self.config_wordlist_files}] did not load, exiting module"
            return False
        return True

    def run_cleanup(self, cleanupList):
        for l in cleanupList:
            self.debug(f"Cleaning up temp file: [{l}]")
            if os.path.exists(l):
                os.remove(l)

    def provision_default_wordlists(self):

        tempfile_dir = self.writeTempWordlist(
            self.config_wordlist_dir, self.config_lines_dir, self.sanity_canary
        )
        self.debug(
            f"Wrote temp DIR wordlist with {str(self.config_lines_dir)} lines to: {tempfile_dir}"
        )
        tempfile_files = self.writeTempWordlist(
            self.config_wordlist_files, self.config_lines_files, self.sanity_canary
        )
        self.debug(
            f"Wrote temp WORDS wordlist with {str(self.config_lines_files)} lines to: {tempfile_files}"
        )
        return tempfile_dir, tempfile_files

    def handle_event(self, event):

        # setup for both event types
        raw_url = event.data
        parsed_url = urlparse(raw_url)
        default_tempfile_dir, default_tempfile_files = self.provision_default_wordlists()
        cleanup_list = [default_tempfile_dir, default_tempfile_dir]

        skip_dir_check = False
        root_stub = "/".join(parsed_url.path.split("/")[:-1])
        root_url = f"{parsed_url.scheme}://{parsed_url.netloc}{root_stub}/"
        depth = len(parsed_url.path.rstrip("/").split("/")) - 1
        self.debug(f"URL depth is: {str(depth)}")
        if depth > self.config_max_depth:
            self.debug(f"Exceeded max depth, aborting event")
            return

        if event.type == "URL_HINT":
            filename_hint = parsed_url.path.rsplit(".", 1)[0].split("/")[-1]

            # if its a URL_HINT and its a file, we need to lock the extension(s) in for everything now
            if "file" in event.tags:
                extension_hint = parsed_url.path.rsplit(".", 1)[1]
                used_extensions = []
                used_extensions.append(extension_hint)
                for ex in self.extension_helper.keys():
                    if extension_hint == ex:
                        for ex2 in self.extension_helper[ex]:
                            used_extensions.append(ex2)
                self.extension_list = used_extensions

        # For prefix busting as they pertain to URL_HINTS, we need to run it after we limit extensions
        if self.config.get("prefix_busting") == True:
            if depth > 0:
                last_node = self.find_last_node(parsed_url)
                if last_node:
                    prefixes = self.findPrefixes(last_node)
                    for p in prefixes:
                        self.debug(
                            f"found prefix [{p}] in last node [{last_node}], running new FFUF with prefix"
                        )
                        self.execute_ffuf(
                            default_tempfile_dir,
                            default_tempfile_files,
                            event,
                            root_url,
                            prefix=p,
                            skip_dir_check=True,
                        )

        # If we have a URL hint, we now need to reduce the list using the hint
        if event.type == "URL_HINT":

            shortname_tempfile_dir = None
            shortname_tempfile_files = None

            if "file" in event.tags:
                skip_dir_check = True
                shortname_tempfile_files, count = self.writeTempShortname(
                    filename_hint, self.config_wordlist_files, self.sanity_canary
                )
                cleanup_list.append(shortname_tempfile_files)
                self.debug(
                    f"Wrote Shortname [FILE] tempfile [{shortname_tempfile_files}] for node [{filename_hint}] with count: [{str(count)}]"
                )
            else:

                shortname_tempfile_dir, count = self.writeTempShortname(
                    filename_hint, self.config_wordlist_dir, self.sanity_canary
                )
                cleanup_list.append(shortname_tempfile_dir)
                self.debug(
                    f"Wrote Shortname [DIRECTORY] tempfile [{shortname_tempfile_dir}] for node [{filename_hint}] with count: [{str(count)}]"
                )

            self.execute_ffuf(
                shortname_tempfile_dir,
                shortname_tempfile_files,
                event,
                root_url,
                skip_dir_check=skip_dir_check,
            )
        else:
            # if its not a URL_HINT, and we have a file-based URL, just ignore it
            if "." in parsed_url.path.split("/")[-1]:
                return
            else:
                # if we think its a directory, normalize it.
                raw_url = raw_url.rstrip("/") + "/"
            self.execute_ffuf(
                default_tempfile_dir,
                default_tempfile_files,
                event,
                root_url,
                skip_dir_check=skip_dir_check,
            )
        # cleanup
        self.run_cleanup(cleanup_list)

    @staticmethod
    def find_last_node(parsed_url):
        extension_split = parsed_url.path.rsplit(".")
        if len(extension_split) > 1:
            last_node = extension_split[0].split("/")[-1]
        else:
            last_node = None
        return last_node

    def execute_ffuf(
        self, tempfile_dir, tempfile_files, event, url, prefix="", skip_dir_check=False
    ):

        if len(prefix) > 0:
            url = url + prefix

        fuzz_url = f"{url}FUZZ"

        if tempfile_dir:
            command = ["ffuf", "-ac", "-s", "-w", tempfile_dir, "-u", fuzz_url + "/"]
            for found_dir in self.helpers.run_live(command):
                if found_dir.rstrip() == self.sanity_canary:
                    self.debug(
                        "Found sanity canary! aborting remainder of run to avoid junk data..."
                    )
                    break
                self.emit_event(f"{url}{found_dir.rstrip()}/", "URL", source=event, tags=["dir"])

        if not self.config.get("dirs_only") and tempfile_files:
            for extension in self.extension_list:
                extension = extension.rstrip()
                file_fuzz_url = f"{fuzz_url}.{extension}"
                command = ["ffuf", "-ac", "-s", "-w", tempfile_files, "-u", file_fuzz_url]
                for found_file in self.helpers.run_live(command):
                    if found_file.rstrip() == self.sanity_canary:
                        self.debug(
                            "Found sanity canary! aborting remainder of run to avoid junk data..."
                        )
                        break
                    found_file_uri = f"{found_file.rstrip()}.{extension}"
                    self.debug(found_file_uri)
                    self.emit_event(
                        f"{url}{found_file_uri.rstrip()}",
                        "URL",
                        source=event,
                        tags=["uri"],
                    )

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

    @staticmethod
    def writeTempShortname(prefix, sourceList, sanity_canary):

        count = 1
        randname = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        tempfilename = f"/tmp/{randname}"
        tempfile = open(tempfilename, "w")
        with open(sourceList) as f:
            for line in f:
                if line.startswith(prefix):
                    count += 1
                    tempfile.write(line)
        tempfile.write(prefix)
        tempfile.close()
        return tempfilename, count

    @staticmethod
    def num_there(s):
        return any(i.isdigit() for i in s)

    def findPrefixes(self, hint):

        # populate the prefix wordlist
        prefixlist = self.helpers.download(
            "https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt",
            cache_hrs=720,
        )
        node_prefixes = []
        # if we can see common prefix delimeters within the shortname, treat them like delimeters
        if "_" in hint:
            node_prefixes.append(hint.split("_")[0] + "_")

        if "-" in hint:
            node_prefixes.append(hint.split("-")[0] + "-")

        # if the shortname fully contains a word, treat it as a prefix
        with open(prefixlist) as f:
            for word in f:
                word = word.rstrip().lower()
                if hint.startswith(word):
                    # we don't want things that are already trying to function like a prefix
                    if ("_" not in word) and ("-" not in word) and (not self.num_there(word)):
                        # using very short prefixes is not productive
                        if len(word) >= 3:
                            node_prefixes.append(word)

                elif word.startswith(hint):
                    # check difference in length
                    if (
                        (len(hint) > 3)
                        and ("_" not in word)
                        and ("-" not in word)
                        and ("." not in word)
                    ):
                        max_distance = 3
                        if (len(word) - len(hint)) <= max_distance:
                            node_prefixes.append(word)
        return node_prefixes
