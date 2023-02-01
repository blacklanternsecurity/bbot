from .header_brute import header_brute
from bbot.core.errors import ScanCancelledError


class getparam_brute(header_brute):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["brute-force", "active", "aggressive", "slow", "web-paramminer"]
    meta = {"description": "Check for common HTTP GET parameters"}

    options = {"wordlist": "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params"}
    options_desc = {"wordlist": "Define the wordlist to be used to derive GET params"}
    scanned_hosts = []
    getparam_blacklist = []
    max_threads = 12
    in_scope_only = True
    compare_mode = "getparam"

    def check_batch(self, compare_helper, url, getparam_list):
        if self.scan.stopping:
            raise ScanCancelledError()
        test_getparams = {p: self.rand_string(14) for p in getparam_list}
        return compare_helper.compare(self.helpers.add_get_params(url, test_getparams).geturl())

    def gen_count_args(self, url):
        getparam_count = 40
        while 1:
            if getparam_count < 0:
                break
            fake_getparams = {self.rand_string(14): self.rand_string(14) for _ in range(0, getparam_count)}
            yield getparam_count, (self.helpers.add_get_params(url, fake_getparams).geturl(),), {}
            getparam_count -= 5

    def clean_list(self, getparam):
        if (len(getparam) > 0) and (getparam.strip() not in self.getparam_blacklist):
            return True
        return False
