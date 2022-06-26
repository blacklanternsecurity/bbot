from .base import BaseModule
from time import sleep

# from urllib.parse import urlparse
from itertools import zip_longest as izip_longest


def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return izip_longest(*args, fillvalue=fillvalue)


def split_list(alist, wanted_parts=2):
    length = len(alist)
    return [alist[i * length // wanted_parts : (i + 1) * length // wanted_parts] for i in range(wanted_parts)]


"""
Todo: 

- clean up requests call in helper
- handle cases where urls including parameters are send
- include options like host only mode
"""


class header_brute(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["brute-force"]
    options = {"header_wordlist": "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/headers"}
    options_desc = {"header_wordlist": "Define the wordlist to be used to derive headers"}
    scanned_hosts = []
    header_blacklist = [
        "content-length",
        "expect",
        "transfer-encoding",
        "connection",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
    ]
    max_threads = 12
    in_scope_only = True

    def setup(self):

        self.wordlist = self.helpers.download(self.config.get("header_wordlist"), cache_hrs=720)
        return True

    # test detection using a canary to find hosts giving bad results
    def canary_check(self, compare_helper, url, rounds):

        canary_result = True

        for i in range(0, rounds):
            header_group = []
            header_group.append(self.helpers.rand_string(12))
            result_tuple = self.check_header_batch(compare_helper, url, header_group)

            # a nonsense header "caused" a difference, we need to abort
            if result_tuple == False:
                canary_result = False
                break
            sleep(0.1)
        return canary_result

    def handle_event(self, event):

        # parsed_host = urlparse(event.data)
        # host = f"{parsed_host.scheme}://{parsed_host.netloc}/"
        url = event.data
        compare_helper = self.helpers.HttpCompare(url)
        batch_size = self.header_count_test(url)
        if batch_size < 0:
            self.debug("could not resolve batch size, aborting")
            return
        self.debug(f"resolved batch_size at {str(batch_size)}")

        canary_rounds = 3
        if self.canary_check(compare_helper, url, canary_rounds) == False:
            self.debug("aborting due to failed canary check")

        f = open(self.wordlist, errors="ignore")
        fl = f.readlines()
        f.close()

        headers_cleaned = [header.strip() for header in filter(self.clean_header_list, fl)]

        for header_group in grouper(headers_cleaned, batch_size, ""):
            header_group = list(filter(None, header_group))

            result_tuple = self.check_header_batch(compare_helper, url, header_group)
            result = result_tuple[0]
            reason = result_tuple[1]
            reflection = result_tuple[2]
            if result == False:
                self.binary_header_search(compare_helper, url, header_group, event, reason, reflection)

    def check_header_batch(self, compare_helper, url, header_list):

        rand = self.helpers.rand_string()
        test_headers = {}
        for header in header_list:
            test_headers[header] = rand
        result_tuple = compare_helper.compare(url, add_headers=test_headers)
        return result_tuple

    def header_count_test(self, url):

        baseline = self.helpers.request(url)
        if (str(baseline.status_code)[0] == "4") and (str(baseline.status_code)[0] == "5"):
            raise Exception("Baseline request throwing error, cannot proceed")
        header_count = 120
        while 1:

            if header_count < 0:
                return -1
            fake_headers = {}
            for i in range(0, header_count):
                fake_headers[self.helpers.rand_string(14)] = self.helpers.rand_string(14)
            r = self.helpers.request(url, headers=fake_headers)
            if (str(r.status_code)[0] == "4") or (str(r.status_code)[0] == "5"):
                header_count -= 5
            else:
                break
        return header_count

    def clean_header_list(self, header):
        if (len(header) > 0) and ("%" not in header) and (header.strip() not in self.header_blacklist):
            return True
        return False

    def binary_header_search(self, compare_helper, url, header_group, event, reason, reflection):
        self.debug(f"entering recursive binary_header_search with {str(len(header_group))} sized header group")
        if len(header_group) == 1:
            if reflection:
                self.emit_event(
                    f"[HEADER_BRUTEFORCE] Host: [{url}] Header: [{header_group[0]}] Reason: [{reason}] ",
                    "VULNERABILITY",
                    event,
                    tags=["http_reflection"],
                )
            else:
                self.emit_event(
                    f"[HEADER_BRUTEFORCE] Host: [{url}] Header: [{header_group[0]}] Reason: [{reason}] ",
                    "VULNERABILITY",
                    event,
                )
        else:
            for header_group_slice in split_list(header_group):

                result_tuple = self.check_header_batch(compare_helper, url, header_group_slice)
                result = result_tuple[0]
                reason = result_tuple[1]
                reflection = result_tuple[2]
                if result == False:
                    self.binary_header_search(compare_helper, url, header_group_slice, event, reason, reflection)
