import re
import uuid
import logging
from contextlib import suppress
from urllib.parse import urlparse, parse_qs, urlencode, ParseResult

from .punycode import smart_decode_punycode


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


double_slash_regex = re.compile(r"/{2,}")


def clean_url(url):
    """
    Remove query string and fragment, lowercase netloc, remove redundant port

    http://evilcorp.com:80 --> http://evilcorp.com/
    http://eViLcORp.com/ --> http://evilcorp.com/
    http://evilcorp.com/api?user=bob#place --> http://evilcorp.com/api
    """
    parsed = parse_url(url)
    parsed = parsed._replace(netloc=str(parsed.netloc).lower(), fragment="", query="")
    try:
        scheme = parsed.scheme
    except ValueError:
        scheme = "https"
    try:
        port = parsed.port
    except ValueError:
        port = 80 if scheme == "http" else 443
    # remove ports if they're redundant
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        hostname = parsed.hostname
        # special case for IPv6 URLs
        if parsed.netloc.startswith("["):
            hostname = f"[{hostname}]"
        # punycode
        hostname = smart_decode_punycode(hostname)
        parsed = parsed._replace(netloc=hostname)
    # normalize double slashes
    parsed = parsed._replace(path=double_slash_regex.sub("/", parsed.path))
    # append / if path is empty
    if parsed.path == "":
        parsed = parsed._replace(path="/")
    return parsed


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


def collapse_urls(urls, threshold=10):
    """
    Smartly dedupe suspiciously-similar URLs like these:
        - http://evilcorp.com/user/11111/info
        - http://evilcorp.com/user/2222/info
        - http://evilcorp.com/user/333/info
        - http://evilcorp.com/user/44/info
        - http://evilcorp.com/user/5/info

    Useful for cleaning large lists of garbage-riddled URLs from sources like wayback
    """
    url_hashes = {}
    for url in urls:
        new_url = clean_url(url)
        url_hash = hash_url(new_url)
        try:
            url_hashes[url_hash].add(new_url)
        except KeyError:
            url_hashes[url_hash] = {
                new_url,
            }

    for url_hash, new_urls in url_hashes.items():
        # if the number of URLs exceeds the threshold
        if len(new_urls) > threshold:
            # yield only one
            yield next(iter(new_urls))
        else:
            yield from new_urls


def url_depth(url):
    parsed = parse_url(url)
    parsed = parsed._replace(path=double_slash_regex.sub("/", parsed.path))
    split_path = str(parsed.path).strip("/").split("/")
    split_path = [e for e in split_path if e]
    return len(split_path)
