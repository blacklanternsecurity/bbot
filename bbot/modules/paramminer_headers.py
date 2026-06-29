import re
from typing import Union

from bbot.errors import HttpCompareError
from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field

_case_split = re.compile(r"[-_]+")


def _mutate_case(word):
    """
    Multi-word (snake_case/kebab-case) → camelCase: ``user_id`` → ``userId``.
    Single word → Title case: ``admin`` → ``Admin``.
    Returns None if no useful mutation exists.
    """
    parts = _case_split.split(word)
    if len(parts) >= 2:
        head = parts[0]
        tail = "".join(p[:1].upper() + p[1:] for p in parts[1:] if p)
        if not tail:
            return None
        result = head + tail
    else:
        if not word or not word[0].islower():
            return None
        result = word[:1].upper() + word[1:]
    return result if result != word else None


class paramminer_headers(BaseModule):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["WEB_PARAMETER"]
    flags = ["active", "loud", "slow", "web-paramminer"]
    meta = {
        "description": "Use smart brute-force to check for common HTTP header parameters",
        "created_date": "2022-04-15",
        "author": "@liquidsec",
    }

    class Config(BaseModuleConfig):
        wordlist: Union[str, list[str]] = Field(
            "",
            description="Define the wordlist to be used to derive headers. Accepts a list of URLs/paths to merge multiple wordlists (duplicates are removed).",
        )
        recycle_words: bool = Field(
            False, description="Attempt to use words found during the scan on all other endpoints"
        )
        skip_boring_words: bool = Field(True, description="Remove commonly uninteresting words from the wordlist")

    # URLs ending with these extensions are known to be case-insensitive — skip case mutation.
    # (Used by paramminer_getparams and paramminer_cookies; HTTP headers are inherently
    # case-insensitive per RFC 7230 so this isn't relevant to paramminer_headers itself.)
    case_insensitive_extensions = {
        ".aspx",
        ".ashx",
        ".ascx",
        ".asmx",
        ".axd",
        ".cshtml",
        ".vbhtml",
        ".razor",
        ".cfm",
        ".cfc",
    }
    scanned_hosts = []
    boring_words = {
        "accept",
        "accept-encoding",
        "accept-language",
        "action",
        "authorization",
        "cf-connecting-ip",
        "connection",
        "content-encoding",
        "content-length",
        "content-range",
        "content-type",
        "cookie",
        "date",
        "expect",
        "host",
        "if",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
        "javascript",
        "keep-alive",
        "label",
        "max-forwards",
        "negotiate",
        "proxy",
        "range",
        "referer",
        "start",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "vary",
        "waf-stuff-below",
        "x-scanner",
        "x_alto_ajax_key",
        "zaccess-control-request-headers",
        "zaccess-control-request-method",
        "zmax-forwards",
        "zorigin",
        "zreferrer",
        "zvia",
        "zx-request-id",
        "zx-timer",
    }
    _module_threads = 4
    in_scope_only = True
    compare_mode = "header"
    default_wordlist = "paramminer_headers.txt"

    header_regex = re.compile(r"^[!#$%&\'*+\-.^_`|~0-9a-zA-Z]+: [^\r\n]+$")

    async def setup_deps(self):
        wordlist = self.config.get("wordlist", "")
        if not wordlist:
            wordlist = f"{self.helpers.wordlist_dir}/{self.default_wordlist}"
        self.wordlist_file = await self.helpers.wordlist(wordlist)
        self.debug(f"Using wordlist: [{wordlist}]")
        return True

    async def setup(self):
        self.recycle_words = self.config.get("recycle_words", True)
        self.event_dict = {}
        self.already_checked = {}

        # global parameter blacklist (shared with excavate) — known framework/CDN/tracker names
        self.global_blacklist = {p.lower() for p in self.scan.config.get("parameter_blacklist", [])}
        self.global_blacklist_prefixes = tuple(
            p.lower() for p in self.scan.config.get("parameter_blacklist_prefixes", [])
        )

        self.wl = {
            h.strip().lower() for h in self.helpers.read_file(self.wordlist_file) if len(h) > 0 and "%" not in h
        }

        # check against the boring list (if the option is set)
        if self.config.get("skip_boring_words", True):
            self.wl -= self.boring_words
            self.wl -= self.global_blacklist
            if self.global_blacklist_prefixes:
                self.wl = {w for w in self.wl if not w.startswith(self.global_blacklist_prefixes)}

        self.extracted_words_master = set()

        return True

    def _mutate_for_url(self, url, words):
        """Hook for subclasses to expand a word set with URL-aware mutations
        (e.g. paramminer_getparams adds case mutations on case-sensitive backends)."""
        return words

    def rand_string(self, *args, **kwargs):
        return self.helpers.rand_string(*args, **kwargs)

    async def do_mining(self, wl, url, batch_size, compare_helper):
        url_checked = self.already_checked.setdefault(url, set())
        for i in wl:
            if i not in self.wl:
                url_checked.add(hash(i))

        results = set()
        abort_threshold = 15
        try:
            for group in self.helpers.grouper(wl, batch_size):
                async for result, reasons, reflection in self.binary_search(compare_helper, url, group):
                    results.add((result, ",".join(reasons), reflection))
                    if len(results) >= abort_threshold:
                        self.warning(
                            f"Abort threshold ({abort_threshold}) reached, too many {self.compare_mode}s found for url: {url}"
                        )
                        results.clear()
                        assert False
        except AssertionError:
            pass
        return results

    async def process_results(self, event, results):
        url = event.url
        for result, reasons, reflection in results:
            paramtype = self.compare_mode.upper()
            if paramtype == "HEADER":
                if self.header_regex.match(result):
                    self.debug("rejecting parameter as it is not a valid header")
                    continue
            tags = []
            if reflection:
                tags = ["http_reflection"]
            description = f"[Paramminer] {self.compare_mode.capitalize()}: [{result}] Reasons: [{reasons}] Reflection: [{str(reflection)}]"
            reflected = "reflected " if reflection else ""

            await self.emit_event(
                {
                    "host": str(event.host),
                    "url": url,
                    "type": paramtype,
                    "description": description,
                    "name": result,
                    "original_value": None,
                },
                "WEB_PARAMETER",
                event,
                tags=tags,
                context=f'{{module}} scanned {url} and identified {{event.type}}: {reflected}{self.compare_mode} parameter: "{result}"',
            )

    async def handle_event(self, event):
        # If recycle words is enabled, we will collect WEB_PARAMETERS we find to build our list in finish()
        # We also collect any parameters of type "SPECULATIVE"
        if event.type == "WEB_PARAMETER":
            parameter_name = event.data.get("name")
            if self.recycle_words or (event.data.get("type") == "SPECULATIVE"):
                if self.config.get("skip_boring_words", True):
                    if parameter_name in self.boring_words:
                        return
                    lower_name = parameter_name.lower()
                    if lower_name in self.global_blacklist:
                        return
                    if self.global_blacklist_prefixes and lower_name.startswith(self.global_blacklist_prefixes):
                        return
                if parameter_name not in self.wl:  # Ensure it's not already in the wordlist
                    self.extracted_words_master.add(parameter_name)

        elif event.type == "HTTP_RESPONSE":
            url = event.url
            try:
                compare_helper = self.helpers.http_compare(url)
            except HttpCompareError as e:
                self.debug(f"Error initializing compare helper: {e}")
                return
            batch_size = await self.count_test(url)
            if batch_size is None or batch_size <= 0:
                self.debug(f"Failed to get baseline max {self.compare_mode} count, aborting")
                return
            self.debug(f"Resolved batch_size at {str(batch_size)}")

            self.event_dict[url] = (event, batch_size)
            try:
                if not await compare_helper.canary_check(url, mode=self.compare_mode):
                    raise HttpCompareError("failed canary check")
            except HttpCompareError as e:
                self.verbose(f'Aborting "{url}" ({e})')
                return

            try:
                results = await self.do_mining(self._mutate_for_url(url, self.wl), url, batch_size, compare_helper)
            except HttpCompareError as e:
                self.debug(f"Encountered HttpCompareError: [{e}] for URL [{event.url}]")
            await self.process_results(event, results)

    max_count = 95

    async def count_test(self, url):
        baseline = await self.helpers.request(url)
        if baseline is None:
            return
        if str(baseline.status_code)[0] in {"4", "5"}:
            return

        # Binary search for the maximum count the server accepts
        lo, hi = 0, self.max_count
        result = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if mid == 0:
                break
            args, kwargs = self.build_count_test_request(url, mid)
            r = await self.helpers.request(*args, **kwargs)
            if r is not None and str(r.status_code)[0] not in {"4", "5"}:
                result = mid
                lo = mid + 1
            else:
                hi = mid - 1
        return result

    def build_count_test_request(self, url, count):
        """Build a test request with `count` fake parameters. Returns (args, kwargs) for helpers.request()."""
        fake_headers = {self.rand_string(14): self.rand_string(14) for _ in range(count)}
        return (url,), {"headers": fake_headers}

    async def binary_search(self, compare_helper, url, group, reasons=None, reflection=False):
        if reasons is None:
            reasons = []
            self.debug(f"Entering binary_search with {len(group):,} sized group for URL [{url}]")
        if len(group) == 1 and len(reasons) > 0:
            yield group[0], reasons, reflection
        elif len(group) > 1 or (len(group) == 1 and len(reasons) == 0):
            for group_slice in self.helpers.split_list(group):
                match, reasons, reflection, subject_response = await self.check_batch(compare_helper, url, group_slice)
                if match is False:
                    async for r in self.binary_search(compare_helper, url, group_slice, reasons, reflection):
                        yield r

    async def check_batch(self, compare_helper, url, header_list):
        rand = self.rand_string()
        test_headers = {}
        for header in header_list:
            test_headers[header] = rand
        return await compare_helper.compare(url, headers=test_headers, check_reflection=(len(header_list) == 1))

    async def finish(self):
        for url, (event, batch_size) in list(self.event_dict.items()):
            try:
                compare_helper = self.helpers.http_compare(url)
            except HttpCompareError as e:
                self.debug(f"Error initializing compare helper: {e}")
                continue
            url_checked = self.already_checked.get(url, set())
            words_to_process = {
                i for i in self._mutate_for_url(url, self.extracted_words_master) if hash(i) not in url_checked
            }
            try:
                results = await self.do_mining(words_to_process, url, batch_size, compare_helper)
            except HttpCompareError as e:
                self.debug(f"Encountered HttpCompareError: [{e}] for URL [{url}]")
                continue
            await self.process_results(event, results)
            self.already_checked.pop(url, None)

    def _incoming_dedup_hash(self, event):
        # dedup by endpoint structure, not full URL string -- value mutations
        # of the same parameter set (e.g. from lightfuzz probes) are one test surface
        p = getattr(event, "parsed_url", None)
        if p is None:
            return hash(event), ""
        if event.type == "WEB_PARAMETER":
            name = event.data.get("name", "")
            additional_params = event.data.get("additional_params") or {}
            param_keys = tuple(sorted(additional_params.keys()))
        else:
            name = ""
            param_keys = ()
        return hash((event.type, p.scheme, p.netloc, p.path, name, param_keys)), "per_endpoint+keys"

    async def filter_event(self, event):
        if await self._is_http_wildcard_host(event) is True:
            return False, "host is an HTTP wildcard responder"

        # Filter out static endpoints
        ext = getattr(event, "url_extension", None)
        if ext and ext in self.scan.config.get("url_extension_static", []):
            return False

        # We don't need to look at WEB_PARAMETERS that we produced
        if str(event.module).startswith("paramminer"):
            return False

        return True
