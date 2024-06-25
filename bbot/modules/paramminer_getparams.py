from .paramminer_headers import paramminer_headers


class paramminer_getparams(paramminer_headers):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["WEB_PARAMETER"]
    produced_events = ["FINDING"]
    flags = ["active", "aggressive", "slow", "web-paramminer"]
    meta = {
        "description": "Use smart brute-force to check for common HTTP GET parameters",
        "created_date": "2022-06-28",
        "author": "@liquidsec",
    }
    scanned_hosts = []
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
    boring_words = {"utm_source", "utm_campaign", "utm_medium", "utm_term", "utm_content"}
    in_scope_only = True
    compare_mode = "getparam"
    default_wordlist = "paramminer_parameters.txt"

    async def check_batch(self, compare_helper, url, getparam_list):
        test_getparams = {p: self.rand_string(14) for p in getparam_list}
        return await compare_helper.compare(
            self.helpers.add_get_params(url, test_getparams).geturl(), check_reflection=(len(getparam_list) == 1)
        )

    def gen_count_args(self, url):
        getparam_count = 40
        while 1:
            if getparam_count < 0:
                break
            fake_getparams = {self.rand_string(14): self.rand_string(14) for _ in range(0, getparam_count)}
            yield getparam_count, (self.helpers.add_get_params(url, fake_getparams).geturl(),), {}
            getparam_count -= 5
