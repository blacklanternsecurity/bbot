from .header_brute import header_brute
from bbot.core.errors import ScanCancelledError


class cookie_brute(header_brute):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["URL"]
    produced_events = ["FINDING"]
    flags = ["brute-force", "active", "aggressive", "slow", "web-paramminer"]
    meta = {
        "description": "Check for common HTTP cookie parameters",
    }
    options = {"wordlist": "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params"}
    options_desc = {"wordlist": "Define the wordlist to be used to derive cookies"}
    scanned_hosts = []
    cookie_blacklist = []
    max_event_handlers = 12
    in_scope_only = True
    compare_mode = "cookie"

    def check_batch(self, compare_helper, url, cookie_list):
        if self.scan.stopping:
            raise ScanCancelledError()
        cookies = {p: self.rand_string(14) for p in cookie_list}
        return compare_helper.compare(url, cookies=cookies)

    def gen_count_args(self, url):
        cookie_count = 40
        while 1:
            if cookie_count < 0:
                break
            fake_cookies = {self.rand_string(14): self.rand_string(14) for _ in range(0, cookie_count)}
            yield cookie_count, (url,), {"cookies": fake_cookies}
            cookie_count -= 5

    def clean_list(self, cookie):
        if (len(cookie) > 0) and (cookie.strip() not in self.cookie_blacklist):
            return True
        return False
