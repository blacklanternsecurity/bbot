import uuid
import logging
from contextlib import suppress
from urllib.parse import urlparse, parse_qs, urlencode, ParseResult

from .regexes import double_slash_regex


log = logging.getLogger("bbot.core.helpers.url")


def parse_url(url):
    """
    Parse the given URL string or ParseResult object and return a ParseResult.

    This function checks if the input is already a ParseResult object. If it is,
    it returns the object as-is. Otherwise, it parses the given URL string using
    `urlparse`.

    Args:
        url (Union[str, ParseResult]): The URL string or ParseResult object to be parsed.

    Returns:
        ParseResult: A named 6-tuple that contains the components of a URL.

    Examples:
        >>> parse_url('https://www.evilcorp.com')
        ParseResult(scheme='https', netloc='www.evilcorp.com', path='', params='', query='', fragment='')
    """
    if isinstance(url, ParseResult):
        return url
    return urlparse(url)


def add_get_params(url, params, encode=True):
    def _no_encode_quote(s, safe="/", encoding=None, errors=None):
        return s

    """
    Add or update query parameters to the given URL.

    This function takes an existing URL and a dictionary of query parameters,
    updates or adds these parameters to the URL, and returns a new URL.

    Args:
        url (Union[str, ParseResult]): The original URL.
        params (Dict[str, Any]): A dictionary containing the query parameters to be added or updated.

    Returns:
        ParseResult: A named 6-tuple containing the components of the modified URL.

    Examples:
        >>> add_get_params('https://www.evilcorp.com?foo=1', {'bar': 2})
        ParseResult(scheme='https', netloc='www.evilcorp.com', path='', params='', query='foo=1&bar=2', fragment='')

        >>> add_get_params('https://www.evilcorp.com?foo=1', {'foo': 2})
        ParseResult(scheme='https', netloc='www.evilcorp.com', path='', params='', query='foo=2', fragment='')
    """
    parsed = urlparse(url)
    query_params = parsed.query.split("&")

    existing_params = {}
    for param in query_params:
        if "=" in param:
            k, v = param.split("=", 1)
            existing_params[k] = v

    existing_params.update(params)

    if encode:
        new_query = urlencode(existing_params, doseq=True)
    else:
        new_query = urlencode(existing_params, doseq=True, quote_via=_no_encode_quote)

    return parsed._replace(query=new_query)


def get_get_params(url):
    """
    Extract the query parameters from the given URL as a dictionary.

    Args:
        url (Union[str, ParseResult]): The URL from which to extract query parameters.

    Returns:
        Dict[str, List[str]]: A dictionary containing the query parameters and their values.

    Examples:
        >>> get_get_params('https://www.evilcorp.com?foo=1&bar=2')
        {'foo': ['1'], 'bar': ['2']}

        >>> get_get_params('https://www.evilcorp.com?foo=1&foo=2')
        {'foo': ['1', '2']}
    """
    parsed = parse_url(url)
    return dict(parse_qs(parsed.query))


CHAR_LOWER = 1
CHAR_UPPER = 2
CHAR_DIGIT = 4
CHAR_SYMBOL = 8


def charset(p):
    """
    Determine the character set of the given string based on the types of characters it contains.

    Args:
        p (str): The string whose character set is to be determined.

    Returns:
        int: A bitmask representing the types of characters present in the string.
            - CHAR_LOWER = 1: Lowercase alphabets
            - CHAR_UPPER = 2: Uppercase alphabets
            - CHAR_DIGIT = 4: Digits
            - CHAR_SYMBOL = 8: Symbols/Special characters

    Examples:
        >>> charset('abc')
        1

        >>> charset('abcABC')
        3

        >>> charset('abc123')
        5

        >>> charset('!abc123')
        13
    """
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
    """
    Evaluates the type of the given parameter.

    Args:
        p (str): The parameter whose type is to be evaluated.

    Returns:
        int: An integer representing the type of parameter.
            - 1: Integer
            - 2: UUID
            - 3: Other

    Examples:
        >>> param_type('123')
        1

        >>> param_type('550e8400-e29b-41d4-a716-446655440000')
        2

        >>> param_type('abc')
        3
    """
    try:
        int(p)
        return 1
    except Exception:
        with suppress(Exception):
            uuid.UUID(p)
            return 2
    return 3


def hash_url(url):
    """
    Hashes a URL for the purpose of cleaning or collapsing similar URLs.

    Args:
        url (str): The URL to be hashed.

    Returns:
        int: The hash value of the cleaned URL.

    Examples:
        >>> hash_url('https://www.evilcorp.com')
        -7448777882396416944

        >>> hash_url('https://www.evilcorp.com/page/1')
        -8101275613229735915

        >>> hash_url('https://www.evilcorp.com/page/2')
        -8101275613229735915
    """
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
    """
    Calculate the depth of the given URL based on its path components.

    Args:
        url (Union[str, ParseResult]): The URL whose depth is to be calculated.

    Returns:
        int: The depth of the URL, based on its path components.

    Examples:
        >>> url_depth('https://www.evilcorp.com/foo/bar/')
        2

        >>> url_depth('https://www.evilcorp.com/foo//bar/baz/')
        3
    """
    parsed = parse_url(url)
    parsed = parsed._replace(path=double_slash_regex.sub("/", parsed.path))
    split_path = str(parsed.path).strip("/").split("/")
    split_path = [e for e in split_path if e]
    return len(split_path)
