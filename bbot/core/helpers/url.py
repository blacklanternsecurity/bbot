import uuid
import logging
from contextlib import suppress
from urllib.parse import urlparse


log = logging.getLogger("bbot.core.helpers.url")


def param_type(p):
    try:
        int(p)
        return 1
    except Exception:
        with suppress(Exception):
            uuid.UUID(p)
            return 2
    return 3


def clean_url(url):
    """
    Remove query string and fragment, lowercase netloc, remove redundant port

    http://evilcorp.com:80 --> http://evilcorp.com/
    http://eViLcORp.com/ --> http://evilcorp.com/
    http://evilcorp.com/api?user=bob#place --> http://evilcorp.com/api
    """
    parsed = urlparse(str(url).strip())
    parsed = parsed._replace(netloc=str(parsed.netloc).lower(), fragment="", query="")
    # remove ports if they're redundant
    if (parsed.scheme == "http" and parsed.port == 80) or (parsed.scheme == "https" and parsed.port == 443):
        hostname = parsed.hostname
        # special case for IPv6 URLs
        if parsed.netloc.startswith("["):
            hostname = f"[{hostname}]"
        parsed = parsed._replace(netloc=hostname)
    # append / if path is empty
    if parsed.path == "":
        parsed = parsed._replace(path="/")
    return parsed


def hash_url(url):
    parsed = urlparse(url)._replace(fragment="", query="")
    to_hash = [parsed.netloc]
    for segment in parsed.path.split("/"):
        hash_segment = []
        hash_segment.append(len(segment))
        hash_segment.append(param_type(segment))
        dot_split = segment.split(".")
        if len(dot_split) > 1:
            hash_segment.append(dot_split[-1])
        else:
            hash_segment.append("")
        to_hash.append(tuple(hash_segment))
    return hash(tuple(to_hash))


def collapse_urls(urls, threshold=5):
    """
    Smartly dedupe suspiciously-similar URLs like these:
        - http://evilcorp.com/user/11111/info
        - http://evilcorp.com/user/22222/info
        - http://evilcorp.com/user/33333/info
        - http://evilcorp.com/user/44444/info
        - http://evilcorp.com/user/55555/info

    Useful for cleaning large lists of garbage-riddled URLs from sources like wayback
    """
    url_hashes = {}
    for url in urls:
        new_url = clean_url(url).geturl()
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
            # only yield one
            yield next(iter(new_urls))
        else:
            yield from new_urls
