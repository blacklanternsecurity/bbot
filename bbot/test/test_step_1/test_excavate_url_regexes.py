"""Unit tests for the URL regexes used by the excavate URLExtractor.

These tests pin behaviour of the IPv6 host parsing in the YARA rule and the
two Python regex post-filters (``full_url_regex`` / ``full_url_regex_strict``).

They cover the regression in issue #1815: the original patterns rejected
``http://[2001:db8::1]/`` and other IPv6 URLs because the host alternative
only matched word characters and dots.
"""

import yara

from bbot.modules.internal.excavate import excavate
from bbot.test.worker import HTTPSERVER_URL


full_url_regex = excavate.URLExtractor.full_url_regex
full_url_regex_strict = excavate.URLExtractor.full_url_regex_strict
yara_url_rule = yara.compile(source=excavate.URLExtractor.yara_rules["url_full"])


IPV6_URLS = [
    "http://[2001:db8::1]/api",
    "https://[2001:db8::1]:8443/api",
    "http://[::1]/",
    "http://[::1]:8080/path",
    "https://[fe80::dead:beef]/foo/bar.html",
    "http://[fe80::1234:5678:9abc:def0]:80/",
]

NON_IPV6_URLS = [
    "http://example.com/",
    "https://www.example.com:8080/path",
    f"{HTTPSERVER_URL}/",
    "https://asdffoo.test.notreal/some/path",
]


def test_full_url_regex_matches_ipv6():
    for url in IPV6_URLS:
        m = full_url_regex.search(url)
        assert m is not None, f"full_url_regex should match IPv6 URL {url!r}"
        # The captured host should retain the surrounding brackets so the
        # downstream URL parser recognises it as IPv6.
        assert m.group(2).startswith("["), f"host capture missing leading [ for {url!r}: {m.group(2)!r}"


def test_full_url_regex_still_matches_existing_patterns():
    for url in NON_IPV6_URLS:
        assert full_url_regex.search(url) is not None, f"regression: full_url_regex broke for {url!r}"


def test_full_url_regex_strict_matches_ipv6():
    for url in IPV6_URLS:
        assert full_url_regex_strict.match(url) is not None, f"full_url_regex_strict should match IPv6 URL {url!r}"


def test_full_url_regex_strict_still_matches_existing_patterns():
    for url in NON_IPV6_URLS:
        assert full_url_regex_strict.match(url) is not None, f"regression: full_url_regex_strict broke for {url!r}"


def test_yara_url_rule_matches_ipv6():
    for url in IPV6_URLS:
        assert yara_url_rule.match(data=url.encode()), f"YARA url_full rule should match IPv6 URL {url!r}"


def test_yara_url_rule_still_matches_existing_patterns():
    for url in NON_IPV6_URLS:
        assert yara_url_rule.match(data=url.encode()), f"regression: YARA url_full rule broke for {url!r}"
