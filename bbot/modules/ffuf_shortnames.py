import re
import random
import string

from bbot.modules.deadly.ffuf import ffuf
from bbot.core.helpers.misc import parse_list_string


def find_common_prefixes(strings, minimum_set_length=4):
    prefix_candidates = [s[:i] for s in strings if len(s) == 6 for i in range(3, 6)]
    frequency_dict = {item: prefix_candidates.count(item) for item in prefix_candidates}
    frequency_dict = {k: v for k, v in frequency_dict.items() if v >= minimum_set_length}
    prefix_list = list(set(frequency_dict.keys()))

    found_prefixes = set()
    for prefix in prefix_list:
        prefix_frequency = frequency_dict[prefix]
        is_substring = False

        for k, v in frequency_dict.items():
            if prefix != k:
                if prefix in k:
                    is_substring = True
        if not is_substring:
            found_prefixes.add(prefix)
        else:
            if prefix_frequency > v and (len(k) - len(prefix) == 1):
                found_prefixes.add(prefix)
    return list(found_prefixes)


class ffuf_shortnames(ffuf):
    watched_events = ["URL_HINT"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["aggressive", "active", "iis-shortnames", "web-thorough"]
    meta = {
        "description": "Use ffuf in combination IIS shortnames",
        "created_date": "2022-07-05",
        "author": "@liquidsec",
    }

    options = {
        "wordlist": "",  # default is defined within setup function
        "wordlist_extensions": "",  # default is defined within setup function
        "lines": 1000000,
        "max_depth": 1,
        "version": "2.0.0",
        "extensions": "",
        "ignore_redirects": True,
        "find_common_prefixes": False,
        "find_delimiters": True,
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "wordlist_extensions": "Specify wordlist to use when making extension lists",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "max_depth": "the maximum directory depth to attempt to solve",
        "version": "ffuf version",
        "extensions": "Optionally include a list of extensions to extend the keyword with (comma separated)",
        "ignore_redirects": "Explicitly ignore redirects (301,302)",
        "find_common_prefixes": "Attempt to automatically detect common prefixes and make additional ffuf runs against them",
        "find_delimiters": "Attempt to detect common delimiters and make additional ffuf runs against them",
    }

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

    in_scope_only = True

    async def setup(self):
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        wordlist = self.config.get("wordlist", "")
        if not wordlist:
            wordlist = f"{self.helpers.wordlist_dir}/ffuf_shortname_candidates.txt"
        self.debug(f"Using [{wordlist}] for shortname candidate list")
        self.wordlist = await self.helpers.wordlist(wordlist)
        self.wordlist_lines = list(self.helpers.read_file(self.wordlist))

        wordlist_extensions = self.config.get("wordlist_extensions", "")
        if not wordlist_extensions:
            wordlist_extensions = f"{self.helpers.wordlist_dir}/raft-small-extensions-lowercase_CLEANED.txt"
        self.debug(f"Using [{wordlist_extensions}] for shortname candidate extension list")
        self.wordlist_extensions = await self.helpers.wordlist(wordlist_extensions)

        try:
            self.extensions = parse_list_string(self.config.get("extensions", ""))
            self.debug(f"Using custom extensions: [{','.join(self.extensions)}]")
        except ValueError as e:
            self.warning(f"Error parsing extensions: {e}")
            return False

        self.ignore_redirects = self.config.get("ignore_redirects")

        self.per_host_collection = {}
        self.shortname_to_event = {}
        return True

    def build_extension_list(self, event):
        used_extensions = []
        extension_hint = event.parsed.path.rsplit(".", 1)[1].lower().strip()
        if len(extension_hint) == 3:
            with open(self.wordlist_extensions) as f:
                for l in f:
                    l = l.lower().lstrip(".")
                    if l.lower().startswith(extension_hint):
                        used_extensions.append(l.strip())
            return used_extensions
        else:
            return [extension_hint]

    def find_delimiter(self, hint):
        delimiters = ["_", "-"]
        for d in delimiters:
            if d in hint:
                if not hint.startswith(d) and not hint.endswith(d):
                    return d, hint.split(d)[0], hint.split(d)[1]
        return None

    async def filter_event(self, event):
        return True

    async def handle_event(self, event):
        if event.source.type == "URL":
            filename_hint = re.sub(r"~\d", "", event.parsed.path.rsplit(".", 1)[0].split("/")[-1]).lower()

            host = f"{event.source.parsed.scheme}://{event.source.parsed.netloc}/"
            if host not in self.per_host_collection.keys():
                self.per_host_collection[host] = [(filename_hint, event.source.data)]

            else:
                self.per_host_collection[host].append((filename_hint, event.source.data))

            self.shortname_to_event[filename_hint] = event

            root_stub = "/".join(event.parsed.path.split("/")[:-1])
            root_url = f"{event.parsed.scheme}://{event.parsed.netloc}{root_stub}/"

            if "shortname-file" in event.tags:
                used_extensions = self.build_extension_list(event)

            if len(filename_hint) == 6:
                tempfile, tempfile_len = self.generate_templist(prefix=filename_hint)
                self.verbose(
                    f"generated temp word list of size [{str(tempfile_len)}] for filename hint: [{filename_hint}]"
                )

            else:
                tempfile = self.helpers.tempfile([filename_hint], pipe=False)
                tempfile_len = 1

            if tempfile_len > 0:
                if "shortname-file" in event.tags:
                    for ext in used_extensions:
                        async for r in self.execute_ffuf(tempfile, root_url, suffix=f".{ext}"):
                            await self.emit_event(
                                r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"]
                            )

                elif "shortname-directory" in event.tags:
                    async for r in self.execute_ffuf(tempfile, root_url, exts=["/"]):
                        r_url = f"{r['url'].rstrip('/')}/"
                        await self.emit_event(r_url, "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"])

            if self.config.get("find_delimiters"):
                if "shortname-directory" in event.tags:
                    delimiter_r = self.find_delimiter(filename_hint)
                    if delimiter_r:
                        delimiter, prefix, partial_hint = delimiter_r
                        self.verbose(f"Detected delimiter [{delimiter}] in hint [{filename_hint}]")
                        tempfile, tempfile_len = self.generate_templist(prefix=partial_hint)
                        async for r in self.execute_ffuf(
                            tempfile, root_url, prefix=f"{prefix}{delimiter}", exts=["/"]
                        ):
                            await self.emit_event(
                                r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"]
                            )

                elif "shortname-file" in event.tags:
                    for ext in used_extensions:
                        delimiter_r = self.find_delimiter(filename_hint)
                        if delimiter_r:
                            delimiter, prefix, partial_hint = delimiter_r
                            self.verbose(f"Detected delimiter [{delimiter}] in hint [{filename_hint}]")
                            tempfile, tempfile_len = self.generate_templist(prefix=partial_hint)
                            async for r in self.execute_ffuf(
                                tempfile, root_url, prefix=f"{prefix}{delimiter}", suffix=f".{ext}"
                            ):
                                await self.emit_event(
                                    r["url"], "URL_UNVERIFIED", source=event, tags=[f"status-{r['status']}"]
                                )

    async def finish(self):
        if self.config.get("find_common_prefixes"):
            per_host_collection = dict(self.per_host_collection)
            self.per_host_collection.clear()

            for host, hint_tuple_list in per_host_collection.items():
                hint_list = [x[0] for x in hint_tuple_list]

                common_prefixes = find_common_prefixes(hint_list)
                for prefix in common_prefixes:
                    self.verbose(f"Found common prefix: [{prefix}] for host [{host}]")
                    for hint_tuple in hint_tuple_list:
                        hint, url = hint_tuple
                        if hint.startswith(prefix):
                            partial_hint = hint[len(prefix) :]

                            # safeguard to prevent loading the entire wordlist
                            if len(partial_hint) > 0:
                                tempfile, tempfile_len = self.generate_templist(prefix=partial_hint)

                                if "shortname-directory" in self.shortname_to_event[hint].tags:
                                    self.verbose(
                                        f"Running common prefix check for URL_HINT: {hint} with prefix: {prefix} and partial_hint: {partial_hint}"
                                    )

                                    async for r in self.execute_ffuf(tempfile, url, prefix=prefix, exts=["/"]):
                                        await self.emit_event(
                                            r["url"],
                                            "URL_UNVERIFIED",
                                            source=self.shortname_to_event[hint],
                                            tags=[f"status-{r['status']}"],
                                        )
                                elif "shortname-file" in self.shortname_to_event[hint].tags:
                                    used_extensions = self.build_extension_list(self.shortname_to_event[hint])

                                    for ext in used_extensions:
                                        self.verbose(
                                            f"Running common prefix check for URL_HINT: {hint} with prefix: {prefix}, extension: .{ext}, and partial_hint: {partial_hint}"
                                        )
                                        async for r in self.execute_ffuf(
                                            tempfile, url, prefix=prefix, suffix=f".{ext}"
                                        ):
                                            await self.emit_event(
                                                r["url"],
                                                "URL_UNVERIFIED",
                                                source=self.shortname_to_event[hint],
                                                tags=[f"status-{r['status']}"],
                                            )
