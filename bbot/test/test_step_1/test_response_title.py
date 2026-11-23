import re
import time

import pytest

from bbot.core.helpers.web.response_event import _extract_title


# the regex _extract_title replaced, kept here to check the results still agree
OLD_TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def old_extract_title(body):
    match = OLD_TITLE_REGEX.search(body)
    return match.group(1).strip() if match else ""


@pytest.mark.parametrize(
    "body,expected",
    [
        ("<html><title>Hello</title></html>", "Hello"),
        ("<TITLE>Upper</TITLE>", "Upper"),
        ("<TiTlE>Mixed</tItLe>", "Mixed"),
        ('<title lang="en" class="x">With attrs</title>', "With attrs"),
        ("<title>\n  Multi\n  line\n</title>", "Multi\n  line"),
        ("<title>  padded  </title>", "padded"),
        ("<title></title>", ""),
        ("<title>first</title><title>second</title>", "first"),
        ("<title>unclosed", ""),
        ("<title", ""),
        ("<title>a<title>b", ""),
        ("<title>a<title>b</title>", "a<title>b"),
        ("<title\n>newline in tag</title>", "newline in tag"),
        ("<titlex>prefix</title>", "prefix"),
        ("no title here", ""),
        ("", ""),
    ],
)
def test_extract_title(body, expected):
    assert _extract_title(body) == expected
    assert _extract_title(body) == old_extract_title(body)


@pytest.mark.parametrize("tag", ["<title>", "<title", "<TITLE x>"])
def test_extract_title_worst_case(tag):
    body = tag * (1024 * 1024 // len(tag))
    start = time.perf_counter()
    assert _extract_title(body) == ""
    assert time.perf_counter() - start < 1
