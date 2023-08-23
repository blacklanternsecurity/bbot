import uuid
import logging
from contextlib import suppress
from urllib.parse import urlparse, parse_qs, urlencode, ParseResult

from .regexes import double_slash_regex


log = logging.getLogger("bbot.core.helpers.url")


def parse_url(url):
    if type(url) == ParseResult:
        return url
    return urlparse(url)


def add_get_params(url, params):
    parsed = parse_url(url)
    old_params = dict(parse_qs(parsed.query))
    old_params.update(params)
    return parsed._replace(query=urlencode(old_params, doseq=True))


def get_get_params(url):
    parsed = parse_url(url)
    return dict(parse_qs(parsed.query))


CHAR_LOWER = 1
CHAR_UPPER = 2
CHAR_DIGIT = 4
CHAR_SYMBOL = 8


def charset(p):
    ret = 0
    for c in p:
        if c.islower():
            ret |= CHAR_LOWER
        elif c.isupper():
            ret |= CHAR_UPPER
        elif c.isnumeric():
            ret |= CHAR_DIGIT
        else:
            ret |= CHAR_SYMBOL
    return ret


def param_type(p):
    try:
        int(p)
        return 1
    except Exception:
        with suppress(Exception):
            uuid.UUID(p)
            return 2
    return 3


def hash_url(url):
    parsed = parse_url(url)
    parsed = parsed._replace(fragment="", query="")
    to_hash = [parsed.netloc]
    for segment in parsed.path.split("/"):
        hash_segment = []
        hash_segment.append(charset(segment))
        hash_segment.append(param_type(segment))
        dot_split = segment.split(".")
        if len(dot_split) > 1:
            hash_segment.append(dot_split[-1])
        else:
            hash_segment.append("")
        to_hash.append(tuple(hash_segment))
    return hash(tuple(to_hash))


def url_depth(url):
    parsed = parse_url(url)
    parsed = parsed._replace(path=double_slash_regex.sub("/", parsed.path))
    split_path = str(parsed.path).strip("/").split("/")
    split_path = [e for e in split_path if e]
    return len(split_path)
