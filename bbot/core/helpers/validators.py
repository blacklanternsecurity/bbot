import logging
import ipaddress
from typing import Union
from functools import wraps
from contextlib import suppress

from bbot.core.helpers import regexes
from bbot.errors import ValidationError
from bbot.core.helpers.url import parse_url, hash_url
from bbot.core.helpers.misc import smart_encode_punycode, split_host_port, make_netloc, is_ip

log = logging.getLogger("bbot.core.helpers.validators")


def validator(func):
    """
    Decorator that squashes all errors raised by the wrapped function into a ValueError.

    Args:
        func (Callable): The function to be decorated.

    Returns:
        Callable: The wrapped function.

    Examples:
        >>> @validator
        ... def validate_port(port):
        ...     return max(1, min(65535, int(str(port))))
    """

    @wraps(func)
    def validate_wrapper(*args, **kwargs):
        try:
            return func(*args)
        except Exception as e:
            raise ValueError(f"Validation failed for {args}, {kwargs}: {e}")

    return validate_wrapper


@validator
def validate_port(port: Union[str, int]):
    """
    Validates and sanitizes a port number by ensuring it falls within the allowed range (1-65535).

    Args:
        port (int or str): The port number to validate.

    Returns:
        int: The sanitized port number.

    Raises:
        ValueError: If the port number cannot be converted to an integer or is out of range.

    Examples:
        >>> validate_port(22)
        22

        >>> validate_port(70000)
        65535

        >>> validate_port(-123)
        1
    """
    return max(1, min(65535, int(str(port))))


@validator
def validate_open_port(open_port: Union[str, int]):
    host, port = split_host_port(open_port)
    port = validate_port(port)
    host = validate_host(host)
    if host and port:
        return make_netloc(host, port)


@validator
def validate_host(host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]):
    """
    Validates and sanitizes a host string. This function handles IPv4, IPv6, and domain names.

    It automatically strips ports, trailing periods, and clinging asterisks and dashes.

    Args:
        host (str): The host string to validate.

    Returns:
        str: The sanitized host string.

    Raises:
        ValidationError: If the host is invalid or does not conform to IPv4, IPv6, or DNS_NAME formats.

    Examples:
        >>> validate_host("2001:db8::ff00:42:8329")
        '2001:db8::ff00:42:8329'

        >>> validate_host("192.168.0.1:443")
        '192.168.0.1'

        >>> validate_host(".*.eViLCoRP.com.")
        'evilcorp.com'

        >>> validate_host("Invalid<>Host")
        ValueError: Validation failed for ('Invalid<>Host',), {}: Invalid hostname: "invalid<>host"
    """
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
    raise ValidationError(f'Invalid hostname: "{host}"')


@validator
def validate_severity(severity: str):
    severity = str(severity).strip().upper()
    if not severity in ("UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise ValueError(f"Invalid severity: {severity}")
    return severity


@validator
def validate_email(email: str):
    email = smart_encode_punycode(str(email).strip().lower())
    if any(r.match(email) for r in regexes.event_type_regexes["EMAIL_ADDRESS"]):
        return email
    raise ValidationError(f'Invalid email: "{email}"')


def clean_url(url: str, url_querystring_remove=True):
    """
    Cleans and normalizes a URL. This function removes the query string and fragment,
    lowercases the netloc, and removes redundant port numbers.

    Args:
        url (str): The URL string to clean.

    Returns:
        ParseResult: A ParseResult object containing the cleaned URL.

    Examples:
        >>> clean_url("http://evilcorp.com:80")
        ParseResult(scheme='http', netloc='evilcorp.com', path='/', params='', query='', fragment='')

        >>> clean_url("http://eViLcORp.com/")
        ParseResult(scheme='http', netloc='evilcorp.com', path='/', params='', query='', fragment='')

        >>> clean_url("http://evilcorp.com/api?user=bob#place")
        ParseResult(scheme='http', netloc='evilcorp.com', path='/api', params='', query='', fragment='')
    """
    parsed = parse_url(url)

    if url_querystring_remove:
        parsed = parsed._replace(netloc=str(parsed.netloc).lower(), fragment="", query="")
    else:
        parsed = parsed._replace(netloc=str(parsed.netloc).lower(), fragment="")
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


def collapse_urls(*args, **kwargs):
    return list(_collapse_urls(*args, **kwargs))


def _collapse_urls(urls, threshold=10):
    """
    Collapses a list of URLs by deduping similar URLs based on a hashing mechanism.
    Useful for cleaning large lists of noisy URLs, such as those retrieved from wayback.

    Args:
        urls (list): The list of URL strings to collapse.
        threshold (int): The number of allowed duplicate URLs before collapsing.

    Yields:
        str: A deduped URL from the input list.

    Example:
        >>> list(collapse_urls(["http://evilcorp.com/user/11111/info", "http://evilcorp.com/user/2222/info"], threshold=1))
        ["http://evilcorp.com/user/11111/info"]

    """
    log.verbose(f"Collapsing {len(urls):,} URLs")
    url_hashes = {}
    for url in urls:
        try:
            new_url = clean_url(url)
        except ValueError as e:
            log.verbose(f"Failed to clean url {url}: {e}")
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


@validator
def validate_url(url: str):
    return validate_url_parsed(url).geturl()


@validator
def validate_url_parsed(url: str):
    url = str(url).strip()
    if not any(r.match(url) for r in regexes.event_type_regexes["URL"]):
        raise ValidationError(f'Invalid URL: "{url}"')
    return clean_url(url)


def soft_validate(s, t):
    """
    Softly validates a given string against a specified type. This function returns a boolean
    instead of raising an error.

    Args:
        s (str): The string to validate.
        t (str): The type to validate against, e.g., "url" or "host".

    Returns:
        bool: True if the string is valid, False otherwise.

    Raises:
        ValueError: If no validator for the specified type is found.

    Examples:
        >>> soft_validate("http://evilcorp.com", "url")
        True
        >>> soft_validate("evilcorp.com", "url")
        False
        >>> soft_validate("http://evilcorp", "wrong_type")
        ValueError: No validator for type "wrong_type"
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


def is_email(email):
    try:
        validate_email(email)
        return True
    except ValueError:
        return False


class Validators:

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper

    def clean_url(self, url: str):
        url_querystring_remove = self.parent_helper.config.get("url_querystring_remove", True)
        return clean_url(url, url_querystring_remove=url_querystring_remove)

    def validate_url_parsed(self, url: str):
        """
        This version is necessary so that it can be config-aware when needed, to avoid a chicken-egg situation. Currently this is only used by the base event class to sanitize URLs
        """
        url = str(url).strip()
        if not any(r.match(url) for r in regexes.event_type_regexes["URL"]):
            raise ValidationError(f'Invalid URL: "{url}"')
        return self.clean_url(url)
