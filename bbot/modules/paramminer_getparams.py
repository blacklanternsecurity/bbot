import itertools
import string
from typing import Union
from urllib.parse import urlparse


from .paramminer_headers import paramminer_headers, _mutate_case
from bbot.core.config.models import BaseModuleConfig, Field


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
        wordlist: Union[str, list[str]] = Field(
            "",
            description="Define the wordlist to be used to derive headers. Accepts a list of URLs/paths to merge multiple wordlists (duplicates are removed).",
        )
        recycle_words: bool = Field(
            False, description="Attempt to use words found during the scan on all other endpoints"
        )
        skip_boring_words: bool = Field(True, description="Remove commonly uninteresting words from the wordlist")
        mutate_case: bool = Field(
            False,
            description=(
                "Also test case-mutated variants of each entry "
                "(camelCase for snake_case/kebab-case, Title case for single words). "
                "Skipped on URLs with case-insensitive backend extensions like .aspx/.cfm."
            ),
        )
        brute_short: bool = Field(
            False,
            description=(
                "Generate every 1-, 2-, and 3-letter [a-z] combination and add to the wordlist. "
                "Costs ~18,278 extra requests per host; opt-in for thorough scans."
            ),
        )

    boring_words = {"utm_source", "utm_campaign", "utm_medium", "utm_term", "utm_content"}
    in_scope_only = True
    compare_mode = "getparam"
    default_wordlist = "paramminer_parameters.txt"

    async def setup(self):
        result = await super().setup()
        if self.config.get("brute_short", False):
            chars = string.ascii_lowercase
            extra = set()
            for length in (1, 2, 3):
                extra |= {"".join(c) for c in itertools.product(chars, repeat=length)}
            # respect global blacklist + boring words on generated combos
            extra -= self.boring_words
            extra -= self.global_blacklist
            if self.global_blacklist_prefixes:
                extra = {w for w in extra if not w.startswith(self.global_blacklist_prefixes)}
            self.wl |= extra
            self.debug(f"brute_short: added {len(extra)} 1-3 letter combinations")
        return result

    def _mutate_for_url(self, url, words):
        if not self.config.get("mutate_case", False):
            return words
        path = urlparse(url).path.lower()
        for ext in self.case_insensitive_extensions:
            if path.endswith(ext):
                return words
        mutations = {m for m in (_mutate_case(w) for w in words) if m}
        return words | mutations

    async def check_batch(self, compare_helper, url, getparam_list):
        test_getparams = {p: self.rand_string(14) for p in getparam_list}
        return await compare_helper.compare(
            self.helpers.add_get_params(url, test_getparams).geturl(), check_reflection=(len(getparam_list) == 1)
        )

    max_count = 40

    def build_count_test_request(self, url, count):
        fake_getparams = {self.rand_string(14): self.rand_string(14) for _ in range(count)}
        return (self.helpers.add_get_params(url, fake_getparams).geturl(),), {}
