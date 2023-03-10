from bbot.modules.base import BaseModule
from bbot.core.errors import HttpCompareError, ScanCancelledError


class paramminer_headers(BaseModule):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "slow", "web-paramminer"]
    meta = {"description": "Use smart brute-force to check for common HTTP header parameters"}
    options = {"wordlist": "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/headers"}
    options_desc = {"wordlist": "Define the wordlist to be used to derive headers"}
    scanned_hosts = []
    header_blacklist = [
        "content-length",
        "expect",
        "accept-encoding",
        "transfer-encoding",
        "connection",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
    ]
    max_event_handlers = 12
    in_scope_only = True
    compare_mode = "header"

    def setup(self):
        wordlist_url = self.config.get("wordlist", "")
        self.wordlist = self.helpers.wordlist(wordlist_url)
        return True

    def rand_string(self, *args, **kwargs):
        return self.helpers.rand_string(*args, **kwargs)

    def handle_event(self, event):
        url = event.data
        try:
            compare_helper = self.helpers.http_compare(url)
        except HttpCompareError as e:
            self.debug(e)
            return
        batch_size = self.count_test(url)
        if batch_size == None or batch_size <= 0:
            self.debug(f"Failed to get baseline max {self.compare_mode} count, aborting")
            return
        self.debug(f"Resolved batch_size at {str(batch_size)}")

        if compare_helper.canary_check(url, mode=self.compare_mode) == False:
            self.verbose(f'Aborting "{url}" due to failed canary check')
            return

        fl = [h.strip().lower() for h in self.helpers.read_file(self.wordlist)]

        wordlist_cleaned = list(filter(self.clean_list, fl))

        results = set()
        abort_threshold = 25
        try:
            for group in self.helpers.grouper(wordlist_cleaned, batch_size):
                for result, reasons, reflection in self.binary_search(compare_helper, url, group):
                    results.add((result, ",".join(reasons), reflection))
                    if len(results) >= abort_threshold:
                        self.warning(
                            f"Abort threshold ({abort_threshold}) reached, too many {self.compare_mode}s found"
                        )
                        results.clear()
                        assert False
        except ScanCancelledError:
            return
        except AssertionError:
            pass

        for result, reasons, reflection in results:
            tags = []
            if reflection:
                tags = ["http_reflection"]
            description = f"[Paramminer] {self.compare_mode.capitalize()}: [{result}] Reasons: [{reasons}]"
            self.emit_event(
                {"host": str(event.host), "url": url, "description": description},
                "FINDING",
                event,
                tags=tags,
            )

    def count_test(self, url):
        baseline = self.helpers.request(url)
        if baseline is None:
            return
        if str(baseline.status_code)[0] in ("4", "5"):
            return
        for count, args, kwargs in self.gen_count_args(url):
            r = self.helpers.request(*args, **kwargs)
            if r is not None and not ((str(r.status_code)[0] in ("4", "5"))):
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

    def clean_list(self, header):
        if (len(header) > 0) and ("%" not in header) and (header not in self.header_blacklist):
            return True
        return False

    def binary_search(self, compare_helper, url, group, reasons=None, reflection=False):
        if reasons is None:
            reasons = []
        self.debug(f"Entering recursive binary_search with {len(group):,} sized group")
        if len(group) == 1:
            if reasons:
                yield group[0], reasons, reflection
        elif len(group) > 1:
            for group_slice in self.helpers.split_list(group):
                match, reasons, reflection, subject_response = self.check_batch(compare_helper, url, group_slice)
                if match == False:
                    yield from self.binary_search(compare_helper, url, group_slice, reasons, reflection)
        else:
            self.warning(f"Submitted group of size 0 to binary_search()")

    def check_batch(self, compare_helper, url, header_list):
        if self.scan.stopping:
            raise ScanCancelledError()
        rand = self.rand_string()
        test_headers = {}
        for header in header_list:
            test_headers[header] = rand
        return compare_helper.compare(url, headers=test_headers, check_reflection=(len(header_list) == 1))
