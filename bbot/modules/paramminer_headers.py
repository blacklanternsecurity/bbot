import re

from bbot.errors import HttpCompareError
from bbot.modules.base import BaseModule


class paramminer_headers(BaseModule):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["WEB_PARAMETER"]
    flags = ["active", "aggressive", "slow", "web-paramminer"]
    meta = {
        "description": "Use smart brute-force to check for common HTTP header parameters",
        "created_date": "2022-04-15",
        "author": "@liquidsec",
    }
    options = {
        "wordlist": "",  # default is defined within setup function
        "recycle_words": False,
        "skip_boring_words": True,
    }
    options_desc = {
        "wordlist": "Define the wordlist to be used to derive headers",
        "recycle_words": "Attempt to use words found during the scan on all other endpoints",
        "skip_boring_words": "Remove commonly uninteresting words from the wordlist",
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
    _module_threads = 12
    in_scope_only = True
    compare_mode = "header"
    default_wordlist = "paramminer_headers.txt"

    header_regex = re.compile(r"^[!#$%&\'*+\-.^_`|~0-9a-zA-Z]+: [^\r\n]+$")

    async def setup(self):
        self.recycle_words = self.config.get("recycle_words", True)
        self.event_dict = {}
        self.already_checked = set()
        wordlist = self.config.get("wordlist", "")
        if not wordlist:
            wordlist = f"{self.helpers.wordlist_dir}/{self.default_wordlist}"
        self.debug(f"Using wordlist: [{wordlist}]")
        self.wl = {
            h.strip().lower()
            for h in self.helpers.read_file(await self.helpers.wordlist(wordlist))
            if len(h) > 0 and "%" not in h
        }

        # check against the boring list (if the option is set)
        if self.config.get("skip_boring_words", True):
            self.wl -= self.boring_words
        self.extracted_words_master = set()

        return True

    def rand_string(self, *args, **kwargs):
        return self.helpers.rand_string(*args, **kwargs)

    async def do_mining(self, wl, url, batch_size, compare_helper):
        for i in wl:
            if i not in self.wl:
                h = hash(i + url)
                self.already_checked.add(h)

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
        url = event.data.get("url")
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
                if self.config.get("skip_boring_words", True) and parameter_name in self.boring_words:
                    return
                if parameter_name not in self.wl:  # Ensure it's not already in the wordlist
                    self.debug(f"Adding {parameter_name} to wordlist")
                    self.extracted_words_master.add(parameter_name)

        elif event.type == "HTTP_RESPONSE":
            url = event.data.get("url")
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
                results = await self.do_mining(self.wl, url, batch_size, compare_helper)
            except HttpCompareError as e:
                self.debug(f"Encountered HttpCompareError: [{e}] for URL [{event.data}]")
            await self.process_results(event, results)

    async def count_test(self, url):
        baseline = await self.helpers.request(url)
        if baseline is None:
            return
        if str(baseline.status_code)[0] in {"4", "5"}:
            return
        for count, args, kwargs in self.gen_count_args(url):
            r = await self.helpers.request(*args, **kwargs)
            if r is not None and str(r.status_code)[0] not in {"4", "5"}:
                return count

    def gen_count_args(self, url):
        header_count = 95
        while 1:
            if header_count < 0:
                break
            fake_headers = {}
            for i in range(0, header_count):
                fake_headers[self.rand_string(14)] = self.rand_string(14)
            yield header_count, (url,), {"headers": fake_headers}
            header_count -= 5

    async def binary_search(self, compare_helper, url, group, reasons=None, reflection=False):
        if reasons is None:
            reasons = []
        self.debug(f"Entering recursive binary_search with {len(group):,} sized group")
        if len(group) == 1 and len(reasons) > 0:
            yield group[0], reasons, reflection
        elif len(group) > 1 or (len(group) == 1 and len(reasons) == 0):
            for group_slice in self.helpers.split_list(group):
                match, reasons, reflection, subject_response = await self.check_batch(compare_helper, url, group_slice)
                if match is False:
                    async for r in self.binary_search(compare_helper, url, group_slice, reasons, reflection):
                        yield r
        else:
            self.debug(
                f"binary_search() failed to start with group of size {str(len(group))} and {str(len(reasons))} length reasons"
            )

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
            words_to_process = {
                i for i in self.extracted_words_master.copy() if hash(i + url) not in self.already_checked
            }
            try:
                results = await self.do_mining(words_to_process, url, batch_size, compare_helper)
            except HttpCompareError as e:
                self.debug(f"Encountered HttpCompareError: [{e}] for URL [{url}]")
                continue
            await self.process_results(event, results)

    async def filter_event(self, event):
        # Filter out static endpoints
        if event.data.get("url").endswith(tuple(f".{ext}" for ext in self.config.get("url_extension_static", []))):
            return False

        # We don't need to look at WEB_PARAMETERS that we produced
        if str(event.module).startswith("paramminer"):
            return False

        return True
