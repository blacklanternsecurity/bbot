import random
import string

import blasthttp

from bbot.modules.base import BaseModule


class web_brute(BaseModule):
    watched_events = ["URL"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["active", "loud"]
    meta = {
        "description": "A fast web fuzzer powered by blasthttp",
        "created_date": "2022-04-10",
        "author": "@liquidsec",
    }

    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "lines": 5000,
        "max_depth": 0,
        "extensions": "",
        "ignore_case": False,
        "rate": 0,
        "concurrency": 50,
    }

    options_desc = {
        "wordlist": "Specify wordlist to use when finding directories",
        "lines": "take only the first N lines from the wordlist when finding directories",
        "max_depth": "the maximum directory depth to attempt to solve",
        "extensions": "Optionally include a list of extensions to extend the keyword with (comma separated)",
        "ignore_case": "Only put lowercase words into the wordlist",
        "rate": "Maximum requests per second (0 = unlimited)",
        "concurrency": "Number of concurrent requests per URL being fuzzed",
    }

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

        filters = await self.baseline_fuzz(fixed_url, exts=exts)
        async for r in self.execute_fuzz(self.words, fixed_url, exts=exts, filters=filters):
            await self.emit_event(
                r["url"],
                "URL_UNVERIFIED",
                parent=event,
                tags=[f"status-{r['status']}"],
                context=f"{{module}} brute-forced {event.url} and found {{event.type}}: {{event.data}}",
            )

    async def filter_event(self, event):
        if "endpoint" in event.tags:
            self.debug(f"rejecting URL [{event.url}] because we don't fuzz endpoints")
            return False
        return True

    def _build_batch_headers(self):
        """Build header list for batch requests from scan config."""
        headers = [("User-Agent", self.scan.useragent)]
        for hk, hv in self.scan.custom_http_headers.items():
            headers.append((hk, hv))
        return headers

    def _response_metrics(self, response):
        """Extract metrics from a response for baseline comparison."""
        text = response.text or ""
        return {
            "status": response.status_code,
            "length": len(response.content),
            "words": len(text.split()),
            "lines": text.count("\n") + 1,
        }

    def _batch_response_metrics(self, response):
        """Extract metrics from a raw blasthttp batch response."""
        body = response.body or ""
        return {
            "status": response.status,
            "length": len(response.body_bytes),
            "words": len(body.split()),
            "lines": body.count("\n") + 1,
        }

    def _is_baseline_match(self, metrics, baseline_filter):
        """Return True if the response matches the baseline (i.e. should be filtered OUT)."""
        if baseline_filter.get("abort"):
            return True
        filter_type = baseline_filter.get("type", "status")
        if filter_type == "not_status":
            # Filter anything matching this status (e.g. 404)
            return metrics["status"] == baseline_filter["status"]
        elif filter_type == "status_and_size":
            return metrics["status"] == baseline_filter["status"] and metrics["length"] == baseline_filter["size"]
        elif filter_type == "status_and_words":
            return metrics["status"] == baseline_filter["status"] and metrics["words"] == baseline_filter["words"]
        elif filter_type == "status_and_lines":
            return metrics["status"] == baseline_filter["status"] and metrics["lines"] == baseline_filter["lines"]
        elif filter_type == "status_only":
            return metrics["status"] == baseline_filter["status"]
        return False

    async def baseline_fuzz(self, url, exts=None, prefix="", suffix=""):
        if exts is None:
            exts = [""]
        filters = {}
        headers = self._build_batch_headers()
        proxy = self.scan.http_proxy or None

        for ext in exts:
            self.debug(f"running baseline for URL [{url}] with ext [{ext}]")

            # Generate 4 canary strings of increasing length and batch them
            canary_configs = []
            canary_length = 4
            for _ in range(4):
                canary_word = "".join(random.choice(string.ascii_lowercase) for _ in range(canary_length))
                canary_length += 2
                canary_url = f"{url}{prefix}{canary_word}{suffix}{ext}"
                canary_configs.append(
                    blasthttp.BatchConfig(
                        canary_url,
                        headers=headers,
                        timeout=self.scan.http_timeout,
                        retries=0,
                        verify_certs=False,
                        follow_redirects=False,
                        proxy=proxy,
                    )
                )

            canary_results = []
            canary_waf_count = 0
            results = await self.blast_client.request_batch(canary_configs, 4, rate_limit=self.rate)
            for result in results:
                if result.success:
                    canary_results.append(self._batch_response_metrics(result.response))
                    if await self.helpers.yara.match(self.waf_yara_rules, result.response.body):
                        canary_waf_count += 1

            # If all canary responses are WAF block pages, the WAF is blocking everything
            if canary_waf_count == len(canary_results) and canary_waf_count > 0:
                self.warning(f"All baseline requests for URL [{url}] ext [{ext}] returned WAF block pages, aborting.")
                filters[ext] = {"abort": True, "reason": "WAF_BLOCK_PAGE"}
                continue

            # Check we got all 4 responses
            if len(canary_results) != 4:
                self.warning(
                    f"Could not attain baseline for URL [{url}] ext [{ext}] — only got {len(canary_results)}/4 responses. Possible connectivity issues."
                )
                filters[ext] = {"abort": True, "reason": "CONNECTIVITY_ISSUES"}
                continue

            # If status codes differ across canaries, likely load balancing
            statuses = {r["status"] for r in canary_results}
            if len(statuses) != 1:
                self.warning("Got different status codes for each baseline. This could indicate load balancing")
                filters[ext] = {"abort": True, "reason": "BASELINE_CHANGED_CODES"}
                continue

            baseline_status = canary_results[0]["status"]

            # All 404s — just look for anything not 404
            if baseline_status == 404:
                self.debug("All baseline results were 404, filtering on status != 404")
                filters[ext] = {"type": "not_status", "status": 404}
                continue

            # All 403s — possible WAF
            if baseline_status == 403:
                self.warning("All baseline requests received 403. A WAF may be actively blocking traffic.")

            # All 429s — rate limiting, abort
            if baseline_status == 429:
                self.warning(
                    f"Received 429 (Too Many Requests) for URL [{url}]. A WAF or rate limiter is blocking requests, aborting."
                )
                filters[ext] = {"abort": True, "reason": "RECEIVED_429"}
                continue

            # Try to find a stable metric for AND filtering
            # 1. Same body size across all canaries
            if len({r["length"] for r in canary_results}) == 1:
                self.debug("All baseline results had the same body size, filtering on status + size")
                filters[ext] = {
                    "type": "status_and_size",
                    "status": baseline_status,
                    "size": canary_results[0]["length"],
                }
                continue

            # 2. Same word count
            if len({r["words"] for r in canary_results}) == 1:
                self.debug("All baseline results had the same word count, filtering on status + words")
                filters[ext] = {
                    "type": "status_and_words",
                    "status": baseline_status,
                    "words": canary_results[0]["words"],
                }
                continue

            # 3. Same line count
            if len({r["lines"] for r in canary_results}) == 1:
                self.debug("All baseline results had the same line count, filtering on status + lines")
                filters[ext] = {
                    "type": "status_and_lines",
                    "status": baseline_status,
                    "lines": canary_results[0]["lines"],
                }
                continue

            # Nothing stable — fall back to status-only
            self.debug("No stable baseline metric found, filtering on status only")
            filters[ext] = {"type": "status_only", "status": baseline_status}

        return filters

    async def execute_fuzz(
        self,
        words,
        url,
        prefix="",
        suffix="",
        exts=None,
        filters=None,
        baseline=False,
    ):
        if exts is None:
            exts = [""]
        if filters is None:
            filters = {}

        headers = self._build_batch_headers()
        proxy = self.scan.http_proxy or None

        for ext in exts:
            # Check for abort filter; default to filtering 404s if no filter provided
            ext_filter = filters.get(ext, {"type": "not_status", "status": 404})
            if ext_filter.get("abort"):
                self.warning(f"Skipping fuzz for ext [{ext}]: {ext_filter.get('reason', 'ABORT')}")
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

            # Fire all requests via native blasthttp batch (Rust concurrency)
            results = await self.blast_client.request_batch(configs, self.concurrency, rate_limit=self.rate)

            # Index results by URL for ordered processing
            results_by_url = {}
            for result in results:
                results_by_url[result.url] = result

            # Process in wordlist order so canary (appended last) is checked last
            canary_found = False
            hits = []
            for config in configs:
                if self.scan.stopping:
                    return
                result = results_by_url.get(config.url)
                if result is None or not result.success:
                    continue

                response = result.response
                metrics = self._batch_response_metrics(response)

                # Check if this matches the baseline (should be filtered out)
                if ext_filter and self._is_baseline_match(metrics, ext_filter):
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

                # Filter 3xx redirects to site root — these are soft 404s,
                # not real findings (e.g. mod_userdir sending ~user to /)
                if 300 <= response.status < 400:
                    location = ""
                    for hdr_name, hdr_val in response.headers:
                        if hdr_name.lower() == "location":
                            location = hdr_val
                            break
                    if location in ("/", url):
                        self.debug(f"Filtering redirect-to-root hit: {response.url} -> {location}")
                        continue

                # Filter WAF block pages (can return any status code, including 200)
                if await self.helpers.yara.match(self.waf_yara_rules, response.body):
                    self.debug(f"Filtering WAF block page: {response.url}")
                    continue

                hits.append({"url": response.url, "status": response.status})

            # If canary was found in results, the server is returning everything — abort
            if canary_found and hits:
                self.debug("Found canary in results, all hits are likely false positives — aborting")
                return

            # Mid-scan validation: one canary check per extension
            if hits and not baseline and ext_filter:
                canary_word = "".join(random.choice(string.ascii_lowercase) for _ in range(4))
                canary_url = f"{url}{prefix}{canary_word}{suffix}{ext}"
                canary_configs = [
                    blasthttp.BatchConfig(
                        canary_url,
                        headers=headers,
                        timeout=self.scan.http_timeout,
                        retries=0,
                        verify_certs=False,
                        follow_redirects=False,
                        proxy=proxy,
                    )
                ]
                canary_batch = await self.blast_client.request_batch(canary_configs, 1, rate_limit=self.rate)
                if canary_batch and canary_batch[0].success:
                    canary_metrics = self._batch_response_metrics(canary_batch[0].response)
                    if not self._is_baseline_match(canary_metrics, ext_filter):
                        self.verbose(
                            f"Would have reported {len(hits)} hit(s), but mid-scan baseline check failed. "
                            "This could be due to a WAF turning on mid-scan."
                        )
                        self.verbose(f"Aborting the current run against [{url}]")
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
