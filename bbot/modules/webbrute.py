import random
import string
from typing import Union

import blasthttp

from bbot.core.helpers.diff import HttpCompare
from bbot.core.helpers.web.web import iter_batch_results
from bbot.errors import HttpCompareError
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class webbrute(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["active", "loud"]
    meta = {
        "description": "A fast web fuzzer powered by blasthttp",
        "created_date": "2022-04-10",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        wordlist: Union[str, list[str]] = Field(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
            description="Specify wordlist to use when finding directories. Accepts a list of URLs/paths to merge multiple wordlists (duplicates are removed).",
        )
        lines: int = Field(5000, description="take only the first N lines from the wordlist when finding directories")
        max_depth: int = Field(0, description="the maximum directory depth to attempt to solve")
        extensions: Union[str, list[str]] = Field(
            "",
            description="Optionally include a list of extensions to extend the keyword with (comma separated or YAML list)",
        )
        ignore_case: bool = Field(False, description="Only put lowercase words into the wordlist")
        rate: int = Field(0, description="Maximum requests per second (0 = unlimited)")
        concurrency: int = Field(50, description="Number of concurrent requests per URL being fuzzed")
        avoid_wafs: bool = Field(
            True, description="Avoid running against confirmed WAFs, which are likely to block brute-force requests"
        )

    banned_characters = {" "}
    blacklist = ["images", "css", "image"]

    in_scope_only = True
    _module_threads = 4

    async def setup_deps(self):
        self.wordlist = await self.helpers.wordlist(self.config.get("wordlist"))
        return True

    async def setup(self):
        self.canary = "".join(random.choice(string.ascii_lowercase) for i in range(10))
        self.blast_client = self.helpers.blasthttp
        self.waf_yara_rules = self.helpers.yara.compile_strings(self.helpers.get_waf_strings(), nocase=True)
        wordlist_url = self.config.get("wordlist", "")
        self.debug(f"Using wordlist [{wordlist_url}]")
        self.wordlist_lines = self.generate_wordlist(self.wordlist)
        self.words, words_len = self.generate_templist()
        self.rate = self.config.get("rate", 0) or None
        self.concurrency = self.config.get("concurrency", 50)
        # warn if the module rate limit is less restrictive than the global setting
        global_rate = self.scan.web_config.get("http_rate_limit", 0)
        if self.rate and global_rate and global_rate < self.rate:
            self.info(
                f"Module rate limit ({self.rate} rps) is higher than global http_rate_limit ({global_rate} rps). "
                f"The more restrictive global setting will be used."
            )
        self._host_timeouts = {}
        self._blocked_hosts = set()
        self.verbose(f"Generated dynamic wordlist with length [{str(words_len)}]")
        try:
            self.extensions = self.helpers.chain_lists(self.config.get("extensions", ""), validate=True)
            self.debug(f"Using custom extensions: [{','.join(self.extensions)}]")
        except ValueError as e:
            self.warning(f"Error parsing extensions: {e}")
            return False
        return True

    async def handle_event(self, event):
        if self.helpers.url_depth(event.url) > self.config.get("max_depth"):
            self.debug("Exceeded max depth, aborting event")
            return

        # only fuzz against a directory
        if "." in event.parsed_url.path.split("/")[-1]:
            self.debug("Aborting fuzz as period was detected in right-most path segment (likely a file)")
            return
        else:
            # if we think its a directory, normalize it.
            fixed_url = event.url.rstrip("/") + "/"

        exts = ["", "/"]
        if self.extensions:
            for ext in self.extensions:
                exts.append(f".{ext}")

        netloc = event.parsed_url.netloc
        filters = await self.baseline_fuzz(fixed_url, exts=exts)
        async for r in self.execute_fuzz(self.words, fixed_url, netloc, exts=exts, filters=filters):
            await self.emit_event(
                r["url"],
                "URL_UNVERIFIED",
                parent=event,
                tags=[f"status-{r['status']}"],
                context=f"{{module}} brute-forced {event.url} and found {{event.type}}: {{event.data}}",
            )

    async def filter_event(self, event):
        if "endpoint" in event.tags:
            return False, "webbrute doesn't fuzz endpoints"
        if self.config.get("avoid_wafs", True) and "waf" in event.tags:
            return False, "host is behind a WAF"
        netloc = event.parsed_url.netloc
        if netloc in self._blocked_hosts:
            return False, f"host [{netloc}] is blocked"
        if await self._is_http_wildcard_host(event) is True:
            return False, "host is an HTTP wildcard responder"
        return True

    def _build_batch_headers(self):
        """Build header list for batch requests from scan config."""
        headers = [("User-Agent", self.scan.useragent)]
        for hk, hv in self.scan.custom_http_headers.items():
            headers.append((hk, hv))
        return headers

    # Host-level abort reasons that apply to ALL extensions, not just the one that triggered them.
    HOST_ABORT_REASONS = {"WAF_BLOCK_PAGE", "CONNECTIVITY_ISSUES", "BASELINE_CHANGED_CODES", "RECEIVED_429"}

    async def baseline_fuzz(self, url, exts=None, prefix="", suffix=""):
        if exts is None:
            exts = [""]
        filters = {}
        host_abort = None

        for ext in exts:
            if host_abort is not None:
                filters[ext] = host_abort
                continue

            self.debug(f"running baseline for URL [{url}] with ext [{ext}]")

            canary_url_1 = f"{url}{prefix}{self.helpers.rand_string(8, digits=False)}{suffix}{ext}"
            canary_url_2 = f"{url}{prefix}{self.helpers.rand_string(10, digits=False)}{suffix}{ext}"

            compare = HttpCompare(
                canary_url_1,
                self.helpers,
                allow_redirects=False,
                timeout=self.scan.http_timeout,
                include_cache_buster=False,
                baseline_url_2=canary_url_2,
            )

            try:
                await compare._baseline()
            except HttpCompareError as e:
                self.warning(f"Could not establish baseline for URL [{url}] ext [{ext}]: {e}")
                abort = {"abort": True, "reason": "CONNECTIVITY_ISSUES"}
                filters[ext] = abort
                host_abort = abort
                continue

            baseline_status = compare.baseline.status_code

            if await self.helpers.yara.match(self.waf_yara_rules, compare.baseline.content):
                self.warning(f"Baseline for URL [{url}] ext [{ext}] returned WAF block page, aborting.")
                abort = {"abort": True, "reason": "WAF_BLOCK_PAGE"}
                filters[ext] = abort
                host_abort = abort
                continue

            if baseline_status == 429:
                self.warning(
                    f"Received 429 (Too Many Requests) for URL [{url}]. A WAF or rate limiter is blocking requests, aborting."
                )
                abort = {"abort": True, "reason": "RECEIVED_429"}
                filters[ext] = abort
                host_abort = abort
                continue

            if baseline_status == 403:
                self.warning("All baseline requests received 403. A WAF may be actively blocking traffic.")

            filters[ext] = {"compare": compare}

        return filters

    async def execute_fuzz(
        self,
        words,
        url,
        netloc,
        prefix="",
        suffix="",
        exts=None,
        filters=None,
    ):
        if exts is None:
            exts = [""]
        if filters is None:
            filters = await self.baseline_fuzz(url, exts=exts, prefix=prefix, suffix=suffix)

        headers = self._build_batch_headers()
        proxy = self.scan.http_proxy or None

        for ext in exts:
            if netloc in self._blocked_hosts:
                self.debug(f"Host [{netloc}] is blocked, skipping remaining extensions")
                return

            ext_filter = filters.get(ext, {})
            if ext_filter.get("abort"):
                self.warning(f"Skipping fuzz for ext [{ext}]: {ext_filter.get('reason', 'ABORT')}")
                continue

            compare = ext_filter.get("compare")
            if compare is None:
                self.debug(f"No baseline for ext [{ext}], skipping")
                continue

            # Build batch configs for this extension
            configs = []
            for word in words:
                fuzz_url = f"{url}{prefix}{word}{suffix}{ext}"
                configs.append(
                    blasthttp.BatchConfig(
                        fuzz_url,
                        headers=headers,
                        timeout=self.scan.http_timeout,
                        retries=0,
                        verify_certs=False,
                        follow_redirects=False,
                        proxy=proxy,
                    )
                )

            if not configs:
                continue

            self.debug(f"Fuzzing {len(configs)} URLs for ext [{ext}]")

            # Hits are collected before emission, gated by three false-positive defenses:
            #   1. Canary: a random word is injected into the wordlist. If it "hits",
            #      the server is responding uniquely to everything, so all hits are junk.
            #   2. Mid-scan baseline: after streaming, a fresh random URL is checked
            #      against the baseline. If it no longer matches, the server's behavior
            #      drifted during the scan (e.g. WAF kicked in), so hits are unreliable.
            #   3. Hit cap: if the number of hits exceeds a sqrt-scaled threshold,
            #      something slipped past the baseline (e.g. the server returns subtly
            #      unique content per real word but not per random string). The host is
            #      blocked and all hits are discarded before emission.
            canary_found = False
            hits = []
            async for result in iter_batch_results(
                self.blast_client.request_batch_stream(configs, self.concurrency, rate_limit=self.rate)
            ):
                if self.scan.stopping:
                    return
                if not result.success:
                    self._host_timeouts[netloc] = self._host_timeouts.get(netloc, 0) + 1
                    if self._host_timeouts[netloc] >= 50:
                        self.verbose(f"Host [{netloc}] has {self._host_timeouts[netloc]} timeouts, blocking host")
                        self._blocked_hosts.add(netloc)
                        return
                    continue

                response = result.response

                # HttpCompare: empty diff_reasons = matches baseline = filter out
                diff_reasons = compare._compare_sync(response, response.url)
                if not diff_reasons:
                    continue

                # Extract the word from the URL to check for canary
                word = result.url[len(url) + len(prefix) :]
                if suffix:
                    word = word[: -len(suffix + ext)] if (suffix + ext) else word
                elif ext:
                    word = word[: -len(ext)]
                word = word.rstrip("/")

                if word == self.canary:
                    canary_found = True
                    continue

                # Filter 3xx redirects to site root
                if 300 <= response.status < 400:
                    location = ""
                    for hdr_name, hdr_val in response.headers.items():
                        if hdr_name.lower() == "location":
                            location = hdr_val
                            break
                    if location in ("/", url):
                        self.debug(f"Filtering redirect-to-root hit: {response.url} -> {location}")
                        continue

                # Filter WAF block pages
                if await self.helpers.yara.match(self.waf_yara_rules, response.body):
                    self.debug(f"Filtering WAF block page: {response.url}")
                    continue

                hits.append({"url": response.url, "status": response.status})

            if canary_found and hits:
                self.debug("Found canary in results, all hits are likely false positives -- aborting")
                return

            # Mid-scan validation: does a fresh canary still match baseline?
            if hits:
                canary_url = f"{url}{prefix}{self.helpers.rand_string(8, digits=False)}{suffix}{ext}"
                try:
                    match, reasons, _, _ = await compare.compare(canary_url)
                except HttpCompareError:
                    match = False
                    reasons = ["error"]
                if not match:
                    self.verbose(
                        f"Would have reported {len(hits)} hit(s), but mid-scan baseline check "
                        f"failed ({reasons}). Aborting the current run against [{url}]"
                    )
                    return

            # sqrt-scaled hit cap: ~28 at 50 words, ~40 at 100, ~126 at 1000, ~283 at 5000
            if len(words) >= 50:
                hit_cap = int(4 * (len(words) ** 0.5))
                if len(hits) > hit_cap:
                    self.warning(
                        f"Discarding {len(hits)} hits for [{url}] ext [{ext}] "
                        f"(exceeds cap of {hit_cap}), likely a filtering failure. Blocking host."
                    )
                    self._blocked_hosts.add(netloc)
                    return

            for hit in hits:
                yield hit

    def generate_templist(self, prefix=None):
        """Generate word list from wordlist_lines, filtered by optional prefix."""
        words = []
        if prefix:
            prefix = prefix.strip().lower()
        max_lines = self.config.get("lines")

        for line in self.wordlist_lines[:max_lines]:
            if (not prefix) or line.lower().startswith(prefix):
                words.append(line)

        words.append(self.canary)
        return words, len(words)

    def generate_wordlist(self, wordlist_file):
        seen = {}
        ignore_case = self.config.get("ignore_case", False)
        for line in self.helpers.read_file(wordlist_file):
            line = line.strip()
            if not line:
                continue
            if line in self.blacklist:
                self.debug(f"Skipping adding [{line}] to wordlist because it was in the blacklist")
                continue
            if any(x in line for x in self.banned_characters):
                self.debug(f"Skipping adding [{line}] to wordlist because it has a banned character")
                continue
            if ignore_case:
                line = line.lower()
            seen[line] = None
        return list(seen)
