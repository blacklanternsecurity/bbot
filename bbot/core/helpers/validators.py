import logging
import ipaddress
from contextlib import suppress

from bbot.core.helpers import regexes
from bbot.core.helpers.url import parse_url, hash_url
from bbot.core.helpers.misc import smart_encode_punycode, split_host_port, make_netloc, is_ip

log = logging.getLogger("bbot.core.helpers.validators")


def validator(func):
    """
    Decorator for squashing all errors into ValueError
    """

    def validate_wrapper(*args, **kwargs):
        try:
            return func(*args)
        except Exception as e:
            raise ValueError(f"Validation failed for {args}, {kwargs}: {e}")

    return validate_wrapper


@validator
def validate_port(port):
    return max(1, min(65535, int(str(port))))


@validator
def validate_open_port(open_port):
    host, port = split_host_port(open_port)
    port = validate_port(port)
    host = validate_host(host)
    if host and port:
        return make_netloc(host, port)


@validator
def validate_host(host):
    # stringify, strip and lowercase
    host = str(host).strip().lower()
    # handle IPv6 netlocs
    if host.startswith("["):
        host = host.split("[")[-1].split("]")[0]
    try:
        # try IPv6 first
        ip = ipaddress.IPv6Address(host)
        return str(ip)
    except Exception:
        # if IPv6 fails, strip ports and root zone
        host = host.split(":")[0].rstrip(".")
        try:
            ip = ipaddress.IPv4Address(host)
            return str(ip)
        except Exception:
            # finally, try DNS_NAME
            host = smart_encode_punycode(host)
            # clean asterisks and clinging dashes
            host = host.strip("*.-").replace("*", "")
            for r in regexes.event_type_regexes["DNS_NAME"]:
                if r.match(host):
                    return host
    assert False, f'Invalid hostname: "{host}"'


@validator
def validate_url(url):
    return validate_url_parsed(url).geturl()


@validator
def validate_url_parsed(url):
    url = str(url).strip()
    if not any(r.match(url) for r in regexes.event_type_regexes["URL"]):
        assert False, f'Invalid URL: "{url}"'
    return clean_url(url)


@validator
def validate_severity(severity):
    severity = str(severity).strip().upper()
    if not severity in ("UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError(f"Invalid severity: {severity}")
    return severity


@validator
def validate_email(email):
    email = smart_encode_punycode(str(email).strip().lower())
    if any(r.match(email) for r in regexes.event_type_regexes["EMAIL_ADDRESS"]):
        return email
    assert False, f'Invalid email: "{email}"'


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
    with suppress(Exception):
        port = parsed.port
    if port is None:
        port = 80 if scheme == "http" else 443
    hostname = validate_host(parsed.hostname)
    # remove ports if they're redundant
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    # special case for IPv6 URLs
    netloc = make_netloc(hostname, port)
    # urlparse is special - it needs square brackets even if there's no port
    if is_ip(netloc, version=6):
        netloc = f"[{netloc}]"
    parsed = parsed._replace(netloc=netloc)
    # normalize double slashes
    parsed = parsed._replace(path=regexes.double_slash_regex.sub("/", parsed.path))
    # append / if path is empty
    if parsed.path == "":
        parsed = parsed._replace(path="/")
    return parsed


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


def soft_validate(s, t):
    """
    Friendly validation wrapper that returns True/False instead of raising an error

    is_valid_url = soft_validate("http://evilcorp.com", "url")
    is_valid_host = soft_validate("http://evilcorp.com", "host")
    """
    try:
        validator_fn = globals()[f"validate_{t.strip().lower()}"]
    except KeyError:
        raise ValueError(f'No validator for type "{t}"')
    try:
        validator_fn(s)
        return True
    except ValueError:
        return False
