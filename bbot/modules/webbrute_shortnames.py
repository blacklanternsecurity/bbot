import pickle
import re
import random
import string
from typing import Union

from bbot.modules.webbrute import webbrute
from bbot.core.config.models import BaseModuleConfig, Field


class webbrute_shortnames(webbrute):
    watched_events = ["URL_HINT"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["loud", "active", "iis-shortnames", "web-heavy"]
    meta = {
        "description": "Brute-force IIS shortnames using ML-predicted wordlists",
        "created_date": "2022-07-05",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        wordlist_extensions: Union[str, list[str]] = Field(
            "",
            description="Specify wordlist to use when making extension lists. Accepts a list of URLs/paths to merge multiple wordlists (duplicates are removed).",
        )
        max_depth: int = Field(1, description="the maximum directory depth to attempt to solve")
        extensions: str = Field(
            "", description="Optionally include a list of extensions to extend the keyword with (comma separated)"
        )
        find_common_prefixes: bool = Field(
            False,
            description="Attempt to automatically detect common prefixes and make additional runs against them",
        )
        find_delimiters: bool = Field(
            True, description="Attempt to detect common delimiters and make additional runs against them"
        )
        find_subwords: bool = Field(
            False, description="Attempt to detect subwords and make additional runs against them"
        )
        max_predictions: int = Field(
            250, description="The maximum number of predictions to generate per shortname prefix"
        )
        rate: int = Field(0, description="Rate of requests per second (default: 0)")

    deps_pip = ["numpy"]
    in_scope_only = True

    supplementary_words = ["html", "ajax", "xml", "json", "api"]

    async def generate_templist(self, hint, shortname_type):
        words = await self.helpers.run_in_executor_cpu(self._generate_templist_sync, hint, shortname_type)
        return words, len(words)

    def _generate_templist_sync(self, hint, shortname_type):
        words = set()
        for prediction, score in self.predict(hint, self.max_predictions, model=shortname_type):
            words.add(prediction.lower())
        words.add(self.canary.lower())
        return list(words)

    def predict(self, prefix, n=25, model="endpoint"):
        predictor_name = f"{model}_predictor"
        predictor = getattr(self, predictor_name)
        return predictor.predict(prefix, n)

    @staticmethod
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

    async def setup_deps(self):
        wordlist_extensions = self.config.get("wordlist_extensions", "")
        if not wordlist_extensions:
            wordlist_extensions = f"{self.helpers.wordlist_dir}/raft-small-extensions-lowercase_CLEANED.txt"
        self.debug(f"Using [{wordlist_extensions}] for shortname candidate extension list")
        self.wordlist_extensions = await self.helpers.wordlist(wordlist_extensions)
        return True

    async def setup(self):
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        self.blast_client = self.helpers.blasthttp
        self.waf_yara_rules = self.helpers.yara.compile_strings(self.helpers.get_waf_strings(), nocase=True)
        self.max_predictions = self.config.get("max_predictions")
        self.find_subwords = self.config.get("find_subwords")
        self.rate = self.config.get("rate", 0) or None
        self.concurrency = 50

        class MinimalWordPredictor:
            def __init__(self):
                self.word_frequencies = {}

            def predict(self, prefix, top_n):
                prefix = prefix.lower()
                matches = [(word, freq) for word, freq in self.word_frequencies.items() if word.startswith(prefix)]

                if not matches:
                    return []

                matches.sort(key=lambda x: x[1], reverse=True)
                matches = matches[:top_n]

                max_freq = matches[0][1]
                return [(word, freq / max_freq) for word, freq in matches]

        class CustomUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                if name == "MinimalWordPredictor":
                    return MinimalWordPredictor
                if module.startswith("numpy"):
                    return super().find_class(module, name)
                raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")

        self.info("Loading shortname prediction models, could take a while if not cached")
        endpoint_model = await self.helpers.wordlist(
            "https://raw.githubusercontent.com/blacklanternsecurity/wordpredictor/refs/heads/main/trained_models/endpoints.bin"
        )
        directory_model = await self.helpers.wordlist(
            "https://raw.githubusercontent.com/blacklanternsecurity/wordpredictor/refs/heads/main/trained_models/directories.bin"
        )

        self.debug(f"Loading endpoint model from: {endpoint_model}")
        with open(endpoint_model, "rb") as f:
            unpickler = CustomUnpickler(f)
            self.endpoint_predictor = unpickler.load()

        self.debug(f"Loading directory model from: {directory_model}")
        with open(directory_model, "rb") as f:
            unpickler = CustomUnpickler(f)
            self.directory_predictor = unpickler.load()

        self.subword_list = []
        if self.find_subwords:
            self.debug("Acquiring shortname subword list")
            subwords = await self.helpers.wordlist(
                "https://raw.githubusercontent.com/nltk/nltk_data/refs/heads/gh-pages/packages/corpora/words.zip",
                zip=True,
                zip_filename="words/en",
            )
            with open(subwords, "r") as f:
                subword_list_content = f.readlines()
            self.subword_list = {word.lower().strip() for word in subword_list_content if 3 <= len(word.strip()) <= 5}
            self.debug(f"Created subword_list with {len(self.subword_list)} words")
            self.subword_list = self.subword_list.union(self.supplementary_words)
            self.debug(f"Extended subword_list with supplementary words, total size: {len(self.subword_list)}")

        self.per_host_collection = {}
        self.shortname_to_event = {}
        self._host_timeouts = {}
        self._blocked_hosts = set()

        return True

    def build_extension_list(self, event):
        used_extensions = []
        extension_hint = event.parsed_url.path.rsplit(".", 1)[1].lower().strip()
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
        if "iis-magic-url" in event.tags:
            return False, "iis-magic-url URL_HINTs are not solvable by webbrute_shortnames"
        if event.parent.type != "URL":
            return False, "its parent event is not of type URL"
        return True

    def find_subword(self, word):
        for i in range(len(word), 2, -1):  # Start from full length down to 3 characters
            candidate = word[:i]
            if candidate in self.subword_list:
                leftover = word[i:]
                return candidate, leftover
        return None, word  # No match found, return None and the original word

    async def handle_event(self, event):
        filename_hint = re.sub(r"~\d", "", event.parsed_url.path.rsplit(".", 1)[0].split("/")[-1]).lower()

        if "shortname-endpoint" in event.tags:
            shortname_type = "endpoint"
        elif "shortname-directory" in event.tags:
            shortname_type = "directory"
        else:
            self.error("webbrute_shortnames received URL_HINT without proper 'shortname-' tag")
            return

        host = f"{event.parent.parsed_url.scheme}://{event.parent.parsed_url.netloc}/"
        if host not in self.per_host_collection.keys():
            self.per_host_collection[host] = [(filename_hint, event.parent.url)]
        else:
            self.per_host_collection[host].append((filename_hint, event.parent.url))

        self.shortname_to_event[filename_hint] = event

        root_stub = "/".join(event.parsed_url.path.split("/")[:-1])
        root_url = f"{event.parsed_url.scheme}://{event.parsed_url.netloc}{root_stub}/"
        netloc = event.parsed_url.netloc

        if shortname_type == "endpoint":
            used_extensions = self.build_extension_list(event)

        if len(filename_hint) == 6:
            words, words_len = await self.generate_templist(filename_hint, shortname_type)
            self.verbose(f"generated word list of size [{str(words_len)}] for filename hint: [{filename_hint}]")
        else:
            words = [filename_hint]
            words_len = 1

        if words_len > 0:
            if shortname_type == "endpoint":
                for ext in used_extensions:
                    async for r in self.execute_fuzz(words, root_url, netloc, suffix=f".{ext}"):
                        await self.emit_event(
                            r["url"],
                            "URL_UNVERIFIED",
                            parent=event,
                            tags=[f"status-{r['status']}"],
                            context=f"{{module}} brute-forced {ext.upper()} files at {root_url} and found {{event.type}}: {{event.pretty_string}}",
                        )

            elif shortname_type == "directory":
                async for r in self.execute_fuzz(words, root_url, netloc, exts=["/"]):
                    r_url = f"{r['url'].rstrip('/')}/"
                    await self.emit_event(
                        r_url,
                        "URL_UNVERIFIED",
                        parent=event,
                        tags=[f"status-{r['status']}"],
                        context=f"{{module}} brute-forced directories at {r_url} and found {{event.type}}: {{event.pretty_string}}",
                    )

        if self.config.get("find_delimiters"):
            if "shortname-directory" in event.tags:
                delimiter_r = self.find_delimiter(filename_hint)
                if delimiter_r:
                    delimiter, prefix, partial_hint = delimiter_r
                    self.verbose(f"Detected delimiter [{delimiter}] in hint [{filename_hint}]")
                    words, words_len = await self.generate_templist(partial_hint, "directory")
                    fuzz_prefix = f"{prefix}{delimiter}"
                    async for r in self.execute_fuzz(words, root_url, netloc, prefix=fuzz_prefix, exts=["/"]):
                        await self.emit_event(
                            r["url"],
                            "URL_UNVERIFIED",
                            parent=event,
                            tags=[f"status-{r['status']}"],
                            context=f'{{module}} brute-forced directories with detected prefix "{fuzz_prefix}" and found {{event.type}}: {{event.pretty_string}}',
                        )

            elif "shortname-endpoint" in event.tags:
                for ext in used_extensions:
                    delimiter_r = self.find_delimiter(filename_hint)
                    if delimiter_r:
                        delimiter, prefix, partial_hint = delimiter_r
                        self.verbose(f"Detected delimiter [{delimiter}] in hint [{filename_hint}]")
                        words, words_len = await self.generate_templist(partial_hint, "endpoint")
                        fuzz_prefix = f"{prefix}{delimiter}"
                        async for r in self.execute_fuzz(
                            words, root_url, netloc, prefix=fuzz_prefix, suffix=f".{ext}"
                        ):
                            await self.emit_event(
                                r["url"],
                                "URL_UNVERIFIED",
                                parent=event,
                                tags=[f"status-{r['status']}"],
                                context=f'{{module}} brute-forced {ext.upper()} files with detected prefix "{fuzz_prefix}" and found {{event.type}}: {{event.pretty_string}}',
                            )

        if self.config.get("find_subwords"):
            subword, suffix = self.find_subword(filename_hint)
            if subword:
                if "shortname-directory" in event.tags:
                    words, words_len = await self.generate_templist(suffix, "directory")
                    async for r in self.execute_fuzz(words, root_url, netloc, prefix=subword, exts=["/"]):
                        await self.emit_event(
                            r["url"],
                            "URL_UNVERIFIED",
                            parent=event,
                            tags=[f"status-{r['status']}"],
                            context=f'{{module}} brute-forced directories with detected subword "{subword}" and found {{event.type}}: {{event.pretty_string}}',
                        )
                elif "shortname-endpoint" in event.tags:
                    for ext in used_extensions:
                        words, words_len = await self.generate_templist(suffix, "endpoint")
                        async for r in self.execute_fuzz(words, root_url, netloc, prefix=subword, suffix=f".{ext}"):
                            await self.emit_event(
                                r["url"],
                                "URL_UNVERIFIED",
                                parent=event,
                                tags=[f"status-{r['status']}"],
                                context=f'{{module}} brute-forced {ext.upper()} files with detected subword "{subword}" and found {{event.type}}: {{event.pretty_string}}',
                            )

    async def finish(self):
        if self.config.get("find_common_prefixes"):
            per_host_collection = dict(self.per_host_collection)
            self.per_host_collection.clear()

            for host, hint_tuple_list in per_host_collection.items():
                hint_list = [x[0] for x in hint_tuple_list]

                common_prefixes = self.find_common_prefixes(hint_list)
                for prefix in common_prefixes:
                    self.verbose(f"Found common prefix: [{prefix}] for host [{host}]")
                    for hint_tuple in hint_tuple_list:
                        hint, url = hint_tuple
                        netloc = self.shortname_to_event[hint].parsed_url.netloc
                        if hint.startswith(prefix):
                            if "shortname-endpoint" in self.shortname_to_event[hint].tags:
                                shortname_type = "endpoint"
                            elif "shortname-directory" in self.shortname_to_event[hint].tags:
                                shortname_type = "directory"
                            else:
                                self.error("webbrute_shortnames received URL_HINT without proper 'shortname-' tag")
                                continue

                            partial_hint = hint[len(prefix) :]

                            # safeguard to prevent loading the entire wordlist
                            if len(partial_hint) > 0:
                                words, words_len = await self.generate_templist(partial_hint, shortname_type)

                                if "shortname-directory" in self.shortname_to_event[hint].tags:
                                    self.verbose(
                                        f"Running common prefix check for URL_HINT: {hint} with prefix: {prefix} and partial_hint: {partial_hint}"
                                    )

                                    async for r in self.execute_fuzz(words, url, netloc, prefix=prefix, exts=["/"]):
                                        await self.emit_event(
                                            r["url"],
                                            "URL_UNVERIFIED",
                                            parent=self.shortname_to_event[hint],
                                            tags=[f"status-{r['status']}"],
                                            context=f'{{module}} brute-forced directories with common prefix "{prefix}" and found {{event.type}}: {{event.pretty_string}}',
                                        )
                                elif shortname_type == "endpoint":
                                    used_extensions = self.build_extension_list(self.shortname_to_event[hint])

                                    for ext in used_extensions:
                                        self.verbose(
                                            f"Running common prefix check for URL_HINT: {hint} with prefix: {prefix}, extension: .{ext}, and partial_hint: {partial_hint}"
                                        )
                                        async for r in self.execute_fuzz(
                                            words, url, netloc, prefix=prefix, suffix=f".{ext}"
                                        ):
                                            await self.emit_event(
                                                r["url"],
                                                "URL_UNVERIFIED",
                                                parent=self.shortname_to_event[hint],
                                                tags=[f"status-{r['status']}"],
                                                context=f'{{module}} brute-forced {ext.upper()} files with common prefix "{prefix}" and found {{event.type}}: {{event.pretty_string}}',
                                            )
