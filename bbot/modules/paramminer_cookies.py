from .paramminer_headers import paramminer_headers


class paramminer_cookies(paramminer_headers):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["WEB_PARAMETER"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "slow", "web-paramminer"]
    meta = {
        "description": "Smart brute-force to check for common HTTP cookie parameters",
        "created_date": "2022-06-27",
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
    options_desc = {"wordlist": "Define the wordlist to be used to derive cookies"}
    scanned_hosts = []
    boring_words = set()
    _module_threads = 12
    in_scope_only = True
    compare_mode = "cookie"
    default_wordlist = "paramminer_parameters.txt"

    async def check_batch(self, compare_helper, url, cookie_list):
        cookies = {p: self.rand_string(14) for p in cookie_list}
        return await compare_helper.compare(url, cookies=cookies, check_reflection=(len(cookie_list) == 1))

    def gen_count_args(self, url):
        cookie_count = 40
        while 1:
            if cookie_count < 0:
                break
            fake_cookies = {self.rand_string(14): self.rand_string(14) for _ in range(0, cookie_count)}
            yield cookie_count, (url,), {"cookies": fake_cookies}
            cookie_count -= 5
