from .paramminer_headers import paramminer_headers
from pydantic import Field
from bbot.core.config.models import BaseModuleConfig


class paramminer_getparams(paramminer_headers):
    """
    Inspired by https://github.com/PortSwigger/param-miner
    """

    watched_events = ["HTTP_RESPONSE", "WEB_PARAMETER"]
    produced_events = ["WEB_PARAMETER"]
    flags = ["active", "loud", "slow", "web-paramminer"]
    meta = {
        "description": "Use smart brute-force to check for common HTTP GET parameters",
        "created_date": "2022-06-28",
        "author": "@liquidsec",
    }
    scanned_hosts = []

    class Config(BaseModuleConfig):
        wordlist: str = Field("", description="Define the wordlist to be used to derive headers")
        recycle_words: bool = Field(
            False, description="Attempt to use words found during the scan on all other endpoints"
        )
        skip_boring_words: bool = Field(True, description="Remove commonly uninteresting words from the wordlist")

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
