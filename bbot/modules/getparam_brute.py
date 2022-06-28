from .base import BaseModule
from time import sleep
from bbot.core.errors import HttpCompareError

# from urllib.parse import urlparse
from itertools import zip_longest as izip_longest


def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return izip_longest(*args, fillvalue=fillvalue)


def split_list(alist, wanted_parts=2):
    length = len(alist)
    return [alist[i * length // wanted_parts : (i + 1) * length // wanted_parts] for i in range(wanted_parts)]


class getparam_brute(BaseModule):

    watched_events = ["URL"]
    produced_events = ["VULNERABILITY"]
    flags = ["brute-force", "active"]
    options = {
        "getparam_wordlist": "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params"
    }
    options_desc = {"getparam_wordlist": "Define the wordlist to be used to derive GET params"}
    scanned_hosts = []
    getparam_blacklist = []
    max_threads = 12
    in_scope_only = True

    def setup(self):

        self.wordlist = self.helpers.download(self.config.get("getparam_wordlist"), cache_hrs=720)
        return True

    # test detection using a canary to find hosts giving bad results
    def canary_check(self, compare_helper, url, rounds):

        canary_result = True

        for i in range(0, rounds):
            getparam_group = []
            getparam_group.append(self.helpers.rand_string(12))
            result_tuple = self.check_getparam_batch(compare_helper, url, getparam_group)

            # a nonsense getparam "caused" a difference, we need to abort
            if result_tuple == False:
                canary_result = False
                break
            sleep(0.2)
        return canary_result

    def handle_event(self, event):

        # parsed_host = urlparse(event.data)
        # host = f"{parsed_host.scheme}://{parsed_host.netloc}/"
        url = event.data
        try:
            compare_helper = self.helpers.http_compare(url)
        except HttpCompareError as e:
            self.debug(e)
            return
        batch_size = self.getparam_count_test(url)

        if batch_size == None:
            self.debug("Failed to get baseline max header count, aborting")
            return
        self.debug(f"resolved batch_size at {str(batch_size)}")

        canary_rounds = 5
        if self.canary_check(compare_helper, url, canary_rounds) == False:
            self.debug("aborting due to failed canary check")
            return

        f = open(self.wordlist, errors="ignore")
        fl = f.readlines()
        f.close()

        getparams_cleaned = [getparam.strip() for getparam in filter(self.clean_getparam_list, fl)]

        for getparam_group in grouper(getparams_cleaned, batch_size, ""):
            getparam_group = list(filter(None, getparam_group))

            result_tuple = self.check_getparam_batch(compare_helper, url, getparam_group)
            result = result_tuple[0]
            reason = result_tuple[1]
            reflection = result_tuple[2]
            if result == False:
                self.binary_getparam_search(compare_helper, url, getparam_group, event, reason, reflection)

    def check_getparam_batch(self, compare_helper, url, getparam_list):

        test_getparams = "?"

        for p in getparam_list:
            test_getparams += f"{p}={self.helpers.rand_string(14)}&"

        result_tuple = compare_helper.compare(url + test_getparams.rstrip("&"))
        return result_tuple

    def getparam_count_test(self, url):

        baseline = self.helpers.request(url)
        if (str(baseline.status_code)[0] == "4") and (str(baseline.status_code)[0] == "5"):
            raise Exception("Baseline request throwing error, cannot proceed")
        getparam_count = 40
        while 1:

            if getparam_count < 0:
                return -1
            fake_getparams = "?"
            for i in range(0, getparam_count):
                fake_getparams += f"{self.helpers.rand_string(14)}={self.helpers.rand_string(14)}&"

            r = self.helpers.request(url + fake_getparams.rstrip("&"))
            if (str(r.status_code)[0] == "4") or (str(r.status_code)[0] == "5"):
                getparam_count -= 5
            else:
                break
        return getparam_count

    def clean_getparam_list(self, getparam):
        if (len(getparam) > 0) and (getparam.strip() not in self.getparam_blacklist):
            return True
        return False

    def binary_getparam_search(self, compare_helper, url, getparam_group, event, reason, reflection):
        self.debug(
            f"entering recursive binary_getparam_search with {str(len(getparam_group))} sized GET parameter group"
        )
        if len(getparam_group) == 1:
            if reflection:
                self.emit_event(
                    f"[GETPARAM_BRUTEFORCE] Host: [{url}] getparam: [{getparam_group[0]}] Reason: [{reason}] ",
                    "VULNERABILITY",
                    event,
                    tags=["http_reflection"],
                )
            else:
                self.emit_event(
                    f"[GETPARAM_BRUTEFORCE] Host: [{url}] getparam: [{getparam_group[0]}] Reason: [{reason}] ",
                    "VULNERABILITY",
                    event,
                )
        else:
            for getparam_group_slice in split_list(getparam_group):

                result_tuple = self.check_getparam_batch(compare_helper, url, getparam_group_slice)
                result = result_tuple[0]
                reason = result_tuple[1]
                reflection = result_tuple[2]
                if result == False:
                    self.binary_getparam_search(compare_helper, url, getparam_group_slice, event, reason, reflection)
