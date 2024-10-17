import os
import sys
import copy
import json
import random
import string
import asyncio
import logging
import ipaddress
import regex as re
import subprocess as sp
from pathlib import Path
from contextlib import suppress
from unidecode import unidecode  # noqa F401
from asyncio import create_task, gather, sleep, wait_for  # noqa
from urllib.parse import urlparse, quote, unquote, urlunparse, urljoin  # noqa F401

from .url import *  # noqa F401
from ... import errors
from . import regexes as bbot_regexes
from .names_generator import random_name, names, adjectives  # noqa F401

log = logging.getLogger("bbot.core.helpers.misc")


def is_domain(d):
    """
    Check if the given input represents a domain without subdomains.

    This function takes an input string `d` and returns True if it represents a domain without any subdomains.
    Otherwise, it returns False.

    Args:
        d (str): The input string containing the domain.

    Returns:
        bool: True if the input is a domain without subdomains, False otherwise.

    Examples:
        >>> is_domain("evilcorp.co.uk")
        True

        >>> is_domain("www.evilcorp.co.uk")
        False

    Notes:
        - Port, if present in input, is ignored.
    """
    d, _ = split_host_port(d)
    if is_ip(d):
        return False
    extracted = tldextract(d)
    if extracted.registered_domain:
        if not extracted.subdomain:
            return True
    else:
        return d.count(".") == 1
    return False


def is_subdomain(d):
    """
    Check if the given input represents a subdomain.

    This function takes an input string `d` and returns True if it represents a subdomain.
    Otherwise, it returns False.

    Args:
        d (str): The input string containing the domain or subdomain.

    Returns:
        bool: True if the input is a subdomain, False otherwise.

    Examples:
        >>> is_subdomain("www.evilcorp.co.uk")
        True

        >>> is_subdomain("evilcorp.co.uk")
        False

    Notes:
        - Port, if present in input, is ignored.
    """
    d, _ = split_host_port(d)
    if is_ip(d):
        return False
    extracted = tldextract(d)
    if extracted.registered_domain:
        if extracted.subdomain:
            return True
    else:
        return d.count(".") > 1
    return False


def is_ptr(d):
    """
    Check if the given input represents a PTR record domain.

    This function takes an input string `d` and returns True if it matches the PTR record format.
    Otherwise, it returns False.

    Args:
        d (str): The input string potentially representing a PTR record domain.

    Returns:
        bool: True if the input matches PTR record format, False otherwise.

    Examples:
        >>> is_ptr("wsc-11-22-33-44.evilcorp.com")
        True

        >>> is_ptr("www2.evilcorp.com")
        False
    """
    return bool(bbot_regexes.ptr_regex.search(str(d)))


def is_url(u):
    """
    Check if the given input represents a valid URL.

    This function takes an input string `u` and returns True if it matches any of the predefined URL formats.
    Otherwise, it returns False.

    Args:
        u (str): The input string potentially representing a URL.

    Returns:
        bool: True if the input matches a valid URL format, False otherwise.

    Examples:
        >>> is_url("https://evilcorp.com")
        True

        >>> is_url("not-a-url")
        False
    """
    u = str(u)
    for r in bbot_regexes.event_type_regexes["URL"]:
        if r.match(u):
            return True
    return False


uri_regex = re.compile(r"^([a-z0-9]{2,20})://", re.I)


def is_uri(u, return_scheme=False):
    """
    Check if the given input represents a URI and optionally return its scheme.

    This function takes an input string `u` and returns True if it matches a URI format.
    When `return_scheme` is True, it returns the URI scheme instead of a boolean.

    Args:
        u (str): The input string potentially representing a URI.
        return_scheme (bool, optional): Whether to return the URI scheme. Defaults to False.

    Returns:
        Union[bool, str]: True if the input matches a URI format; the URI scheme if `return_scheme` is True.

    Examples:
        >>> is_uri("http://evilcorp.com")
        True

        >>> is_uri("ftp://evilcorp.com")
        True

        >>> is_uri("evilcorp.com")
        False

        >>> is_uri("ftp://evilcorp.com", return_scheme=True)
        "ftp"
    """
    match = uri_regex.match(u)
    if return_scheme:
        if match:
            return match.groups()[0].lower()
        return ""
    return bool(match)


def split_host_port(d):
    """
    Parse a string containing a host and port into a tuple.

    This function takes an input string `d` and returns a tuple containing the host and port.
    The host is converted to its appropriate IP address type if possible. The port is inferred
    based on the scheme if not provided.

    Args:
        d (str): The input string containing the host and possibly the port.

    Returns:
        Tuple[Union[IPv4Address, IPv6Address, str], Optional[int]]: Tuple containing the host and port.

    Examples:
        >>> split_host_port("evilcorp.com:443")
        ("evilcorp.com", 443)

        >>> split_host_port("192.168.1.1:443")
        (IPv4Address('192.168.1.1'), 443)

        >>> split_host_port("[dead::beef]:443")
        (IPv6Address('dead::beef'), 443)

    Notes:
        - If port is not provided, it is inferred based on the scheme:
            - For "https" and "wss", port 443 is used.
            - For "http" and "ws", port 80 is used.
    """
    d = str(d)
    host = None
    port = None
    scheme = None
    if is_ip(d):
        return make_ip_type(d), port

    match = bbot_regexes.split_host_port_regex.match(d)
    if match is None:
        raise ValueError(f'split_port() failed to parse "{d}"')
    scheme = match.group("scheme")
    netloc = match.group("netloc")
    if netloc is None:
        raise ValueError(f'split_port() failed to parse "{d}"')

    match = bbot_regexes.extract_open_port_regex.match(netloc)
    if match is None:
        raise ValueError(f'split_port() failed to parse netloc "{netloc}" (original value: {d})')

    host = match.group(2)
    if host is None:
        host = match.group(1)
    if host is None:
        raise ValueError(f'split_port() failed to locate host in netloc "{netloc}" (original value: {d})')

    port = match.group(3)
    if port is None and scheme is not None:
        scheme = scheme.lower()
        if scheme in ("https", "wss"):
            port = 443
        elif scheme in ("http", "ws"):
            port = 80
    elif port is not None:
        with suppress(ValueError):
            port = int(port)

    return make_ip_type(host), port


def parent_domain(d):
    """
    Retrieve the parent domain of a given subdomain string.

    This function takes an input string `d` representing a subdomain and returns its parent domain.
    If the input does not represent a subdomain, it returns the input as is.

    Args:
        d (str): The input string representing a subdomain or domain.

    Returns:
        str: The parent domain of the subdomain, or the original input if it is not a subdomain.

    Examples:
        >>> parent_domain("www.internal.evilcorp.co.uk")
        "internal.evilcorp.co.uk"

        >>> parent_domain("www.internal.evilcorp.co.uk:8080")
        "internal.evilcorp.co.uk:8080"

        >>> parent_domain("www.evilcorp.co.uk")
        "evilcorp.co.uk"

        >>> parent_domain("evilcorp.co.uk")
        "evilcorp.co.uk"

    Notes:
        - Port, if present in input, is preserved in the output.
    """
    host, port = split_host_port(d)
    if is_subdomain(d):
        return make_netloc(".".join(str(host).split(".")[1:]), port)
    return d


def domain_parents(d, include_self=False):
    """
    Generate a list of parent domains for a given domain string.

    This function takes an input string `d` and generates a list of parent domains in decreasing order of specificity.
    If `include_self` is set to True, the list will also include the input domain if it is not a top-level domain.

    Args:
        d (str): The input string representing a domain or subdomain.
        include_self (bool, optional): Whether to include the input domain itself. Defaults to False.

    Yields:
        str: Parent domains of the input string in decreasing order of specificity.

    Examples:
        >>> list(domain_parents("test.www.evilcorp.co.uk"))
        ["www.evilcorp.co.uk", "evilcorp.co.uk"]

    Notes:
        - Port, if present in input, is preserved in the output.
    """

    parent = str(d)
    if include_self and not is_domain(parent):
        yield parent
    while 1:
        parent = parent_domain(parent)
        if is_subdomain(parent):
            yield parent
            continue
        elif is_domain(parent):
            yield parent
        break


def subdomain_depth(d):
    """
    Calculate the depth of subdomains within a given domain name.

    Args:
        d (str): The domain name to analyze.

    Returns:
        int: The depth of the subdomain. For example, a hostname "5.4.3.2.1.evilcorp.com"
        has a subdomain depth of 5.
    """
    subdomain, domain = split_domain(d)
    if not subdomain:
        return 0
    return subdomain.count(".") + 1


def parent_url(u):
    """
    Retrieve the parent URL of a given URL.

    This function takes an input string `u` representing a URL and returns its parent URL.
    If the input URL does not have a parent (i.e., it's already the top-level), it returns None.

    Args:
        u (str): The input string representing a URL.

    Returns:
        Union[str, None]: The parent URL of the input URL, or None if it has no parent.

    Examples:
        >>> parent_url("https://evilcorp.com/sub/path/")
        "https://evilcorp.com/sub/"

        >>> parent_url("https://evilcorp.com/")
        None

    Notes:
        - Only the path component of the URL is modified.
        - All other components like scheme, netloc, query, and fragment are preserved.
    """
    parsed = urlparse(u)
    path = Path(parsed.path)
    if path.parent == path:
        return None
    else:
        return urlunparse(parsed._replace(path=str(path.parent), query=""))


def url_parents(u):
    """
    Generate a list of parent URLs for a given URL string.

    This function takes an input string `u` representing a URL and generates a list of its parent URLs in decreasing order of specificity.

    Args:
        u (str): The input string representing a URL.

    Returns:
        List[str]: A list of parent URLs of the input URL in decreasing order of specificity.

    Examples:
        >>> url_parents("http://www.evilcorp.co.uk/admin/tools/cmd.php")
        ["http://www.evilcorp.co.uk/admin/tools/", "http://www.evilcorp.co.uk/admin/", "http://www.evilcorp.co.uk/"]

    Notes:
        - The list is generated by continuously calling `parent_url` until it returns None.
        - All components of the URL except for the path are preserved.
    """
    parent_list = []
    while 1:
        parent = parent_url(u)
        if parent == None:
            return parent_list
        elif parent not in parent_list:
            parent_list.append(parent)
            u = parent


def best_http_status(code1, code2):
    """
    Determine the better HTTP status code between two given codes.

    The 'better' status code is considered based on typical usage and priority in HTTP communication.
    Lower codes are generally better than higher codes. Within the same class (e.g., 2xx), a lower code is better.
    Between different classes, the order of preference is 2xx > 3xx > 1xx > 4xx > 5xx.

    Args:
        code1 (int): The first HTTP status code.
        code2 (int): The second HTTP status code.

    Returns:
        int: The better HTTP status code between the two provided codes.

    Examples:
        >>> better_http_status(200, 404)
        200
        >>> better_http_status(500, 400)
        400
        >>> better_http_status(301, 302)
        301
    """

    # Classify the codes into their respective categories (1xx, 2xx, 3xx, 4xx, 5xx)
    def classify_code(code):
        return int(code) // 100

    class1 = classify_code(code1)
    class2 = classify_code(code2)

    # Priority order for classes
    priority_order = {2: 1, 3: 2, 1: 3, 4: 4, 5: 5}

    # Compare based on class priority
    p1 = priority_order.get(class1, 10)
    p2 = priority_order.get(class2, 10)
    if p1 != p2:
        return code1 if p1 < p2 else code2

    # If in the same class, the lower code is better
    return min(code1, code2)


def tldextract(data):
    """
    Extracts the subdomain, domain, and suffix from a URL string.

    Args:
        data (str): The URL string to be processed.

    Returns:
        ExtractResult: A named tuple containing the subdomain, domain, and suffix.

    Examples:
        >>> tldextract("www.evilcorp.co.uk")
        ExtractResult(subdomain='www', domain='evilcorp', suffix='co.uk')

    Notes:
        - Utilizes `smart_decode` to preprocess the data.
        - Makes use of the `tldextract` library for extraction.
    """
    import tldextract as _tldextract

    return _tldextract.extract(smart_decode(data))


def split_domain(hostname):
    """
    Splits the hostname into its subdomain and registered domain components.

    Args:
        hostname (str): The full hostname to be split.

    Returns:
        tuple: A tuple containing the subdomain and registered domain.

    Examples:
        >>> split_domain("www.internal.evilcorp.co.uk")
        ("www.internal", "evilcorp.co.uk")

    Notes:
        - Utilizes the `tldextract` function to first break down the hostname.
    """
    if is_ip(hostname):
        return ("", hostname)
    parsed = tldextract(hostname)
    subdomain = parsed.subdomain
    domain = parsed.registered_domain
    if not domain:
        split = hostname.split(".")
        subdomain = ".".join(split[:-2])
        domain = ".".join(split[-2:])
    return (subdomain, domain)


def domain_stem(domain):
    """
    Returns an abbreviated representation of the hostname by removing the TLD (Top-Level Domain).

    Args:
        domain (str): The full domain name to be abbreviated.

    Returns:
        str: An abbreviated domain string without the TLD.

    Examples:
        >>> domain_stem("www.evilcorp.com")
        "www.evilcorp"

    Notes:
        - Utilizes the `tldextract` function for domain parsing.
    """
    parsed = tldextract(str(domain))
    return f".".join(parsed.subdomain.split(".") + parsed.domain.split(".")).strip(".")


def ip_network_parents(i, include_self=False):
    """
    Generates all parent IP networks for a given IP address or network, optionally including the network itself.

    Args:
        i (str or ipaddress.IPv4Network/ipaddress.IPv6Network): The IP address or network to find parents for.
        include_self (bool, optional): Whether to include the network itself in the result. Default is False.

    Yields:
        ipaddress.IPv4Network or ipaddress.IPv6Network: Parent IP networks in descending order of prefix length.

    Examples:
        >>> list(ip_network_parents("192.168.1.1"))
        [ipaddress.IPv4Network('192.168.1.0/31'), ipaddress.IPv4Network('192.168.1.0/30'), ... , ipaddress.IPv4Network('0.0.0.0/0')]

    Notes:
        - Utilizes Python's built-in `ipaddress` module for network operations.
    """
    net = ipaddress.ip_network(i, strict=False)
    for i in range(net.prefixlen - (0 if include_self else 1), -1, -1):
        yield ipaddress.ip_network(f"{net.network_address}/{i}", strict=False)


def is_port(p):
    """
    Checks if the given string represents a valid port number.

    Args:
        p (str or int): The port number to check.

    Returns:
        bool: True if the port number is valid, False otherwise.

    Examples:
        >>> is_port('80')
        True
        >>> is_port('70000')
        False
    """

    p = str(p)
    return p and p.isdigit() and 0 <= int(p) <= 65535


def is_dns_name(d, include_local=True):
    """
    Determines if the given string is a valid DNS name.

    Args:
        d (str): The string to be checked.
        include_local (bool): Consider local hostnames to be valid (hostnames without periods)

    Returns:
        bool: True if the string is a valid DNS name, False otherwise.

    Examples:
        >>> is_dns_name('www.example.com')
        True
        >>> is_dns_name('localhost')
        True
        >>> is_dns_name('localhost', include_local=False)
        False
        >>> is_dns_name('192.168.1.1')
        False
    """
    if is_ip(d):
        return False
    d = smart_decode(d)
    if include_local:
        if bbot_regexes.hostname_regex.match(d):
            return True
    if bbot_regexes.dns_name_regex.match(d):
        return True
    return False


def is_ip(d, version=None):
    """
    Checks if the given string or object represents a valid IP address.

    Args:
        d (str or ipaddress.IPvXAddress): The IP address to check.
        version (int, optional): The IP version to validate (4 or 6). Default is None.

    Returns:
        bool: True if the string or object is a valid IP address, False otherwise.

    Examples:
        >>> is_ip('192.168.1.1')
        True
        >>> is_ip('bad::c0de', version=6)
        True
        >>> is_ip('bad::c0de', version=4)
        False
        >>> is_ip('evilcorp.com')
        False
    """
    try:
        ip = ipaddress.ip_address(d)
        if version is None or ip.version == version:
            return True
    except Exception:
        pass
    return False


def is_ip_type(i, network=None):
    """
    Checks if the given object is an instance of an IPv4 or IPv6 type from the ipaddress module.

    Args:
        i (ipaddress._BaseV4 or ipaddress._BaseV6): The IP object to check.
        network (bool, optional): Whether to restrict the check to network types (IPv4Network or IPv6Network). Defaults to False.

    Returns:
        bool: True if the object is an instance of ipaddress._BaseV4 or ipaddress._BaseV6, False otherwise.

    Examples:
        >>> is_ip_type(ipaddress.IPv6Address('dead::beef'))
        True
        >>> is_ip_type(ipaddress.IPv4Network('192.168.1.0/24'))
        True
        >>> is_ip_type("192.168.1.0/24")
        False
    """
    if network is not None:
        is_network = ipaddress._BaseNetwork in i.__class__.__mro__
        if network:
            return is_network
        else:
            return not is_network
    return ipaddress._IPAddressBase in i.__class__.__mro__


def make_ip_type(s):
    """
    Convert a string to its corresponding IP address or network type.

    This function attempts to convert the input string `s` into either an IPv4 or IPv6 address object,
    or an IPv4 or IPv6 network object. If none of these conversions are possible, the original string is returned.

    Args:
        s (str): The input string to be converted.

    Returns:
        Union[IPv4Address, IPv6Address, IPv4Network, IPv6Network, str]: The converted object or original string.

    Examples:
        >>> make_ip_type("dead::beef")
        IPv6Address('dead::beef')

        >>> make_ip_type("192.168.1.0/24")
        IPv4Network('192.168.1.0/24')

        >>> make_ip_type("evilcorp.com")
        'evilcorp.com'
    """
    if not s:
        raise ValueError(f'Invalid hostname: "{s}"')
    # IP address
    with suppress(Exception):
        return ipaddress.ip_address(s)
    # IP network
    with suppress(Exception):
        return ipaddress.ip_network(s, strict=False)
    return s


def sha1(data):
    """
    Computes the SHA-1 hash of the given data.

    Args:
        data (str or dict): The data to hash. If a dictionary, it is first converted to a JSON string with sorted keys.

    Returns:
        hashlib.Hash: SHA-1 hash object of the input data.

    Examples:
        >>> sha1("asdf").hexdigest()
        '3da541559918a808c2402bba5012f6c60b27661c'
    """
    from hashlib import sha1 as hashlib_sha1

    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    return hashlib_sha1(smart_encode(data))


def smart_decode(data):
    """
    Decodes the input data to a UTF-8 string, silently ignoring errors.

    Args:
        data (str or bytes): The data to decode.

    Returns:
        str: The decoded string.

    Examples:
        >>> smart_decode(b"asdf")
        "asdf"
        >>> smart_decode("asdf")
        "asdf"
    """
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    else:
        return str(data)


def smart_encode(data):
    """
    Encodes the input data to bytes using UTF-8 encoding, silently ignoring errors.

    Args:
        data (str or bytes): The data to encode.

    Returns:
        bytes: The encoded bytes.

    Examples:
        >>> smart_encode("asdf")
        b"asdf"
        >>> smart_encode(b"asdf")
        b"asdf"
    """
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8", errors="ignore")


encoded_regex = re.compile(r"%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\[ntrbv]")
backslash_regex = re.compile(r"(?P<slashes>\\+)(?P<char>[ntrvb])")


def ensure_utf8_compliant(text):
    return text.encode("utf-8", errors="ignore").decode("utf-8")


def recursive_decode(data, max_depth=5):
    """
    Recursively decodes doubly or triply-encoded strings to their original form.

    Supports both URL-encoding and backslash-escapes (including unicode)

    Args:
        data (str): The data to decode.
        max_depth (int, optional): Maximum recursion depth for decoding. Defaults to 5.

    Returns:
        str: The decoded string.

    Examples:
        >>> recursive_decode("Hello%20world%21")
        "Hello world!"
        >>> recursive_decode("Hello%20%5Cu041f%5Cu0440%5Cu0438%5Cu0432%5Cu0435%5Cu0442")
        "Hello Привет"
        >>> recursive_dcode("%5Cu0020%5Cu041f%5Cu0440%5Cu0438%5Cu0432%5Cu0435%5Cu0442%5Cu0021")
        " Привет!"
    """
    import codecs

    # Decode newline and tab escapes
    data = backslash_regex.sub(
        lambda match: {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "v": "\v"}.get(match.group("char")), data
    )
    data = smart_decode(data)
    if max_depth == 0:
        return data
    # Decode URL encoding
    data = unquote(data, errors="ignore")
    # Decode Unicode escapes
    with suppress(UnicodeEncodeError):
        data = ensure_utf8_compliant(codecs.decode(data, "unicode_escape", errors="ignore"))
    # Check if there's still URL-encoded or Unicode-escaped content
    if encoded_regex.search(data):
        # If yes, continue decoding
        return recursive_decode(data, max_depth=max_depth - 1)
    return data


rand_pool = string.ascii_lowercase
rand_pool_digits = rand_pool + string.digits


def rand_string(length=10, digits=True):
    """
    Generates a random string of specified length.

    Args:
        length (int, optional): The length of the random string. Defaults to 10.
        digits (bool, optional): Whether to include digits in the string. Defaults to True.

    Returns:
        str: A random string of the specified length.

    Examples:
        >>> rand_string()
        'c4hp4i9jzx'
        >>> rand_string(20)
        'ap4rsdtg5iw7ey7y3oa5'
        >>> rand_string(30, digits=False)
        'xdmyxtglqfzqktngkesyulwbfrihva'
    """
    pool = rand_pool
    if digits:
        pool = rand_pool_digits
    return "".join([random.choice(pool) for _ in range(int(length))])


def truncate_string(s, n):
    if len(s) > n:
        return s[: n - 3] + "..."
    else:
        return s


def extract_params_json(json_data, compare_mode="getparam"):
    """
    Extracts key-value pairs from a JSON object and returns them as a set of tuples. Used by the `paramminer_headers` module.

    Args:
        json_data (str): JSON-formatted string containing key-value pairs.

    Returns:
        set: A set of tuples containing the keys and their corresponding values present in the JSON object.

    Raises:
        Returns an empty set if JSONDecodeError occurs.

    Examples:
        >>> extract_params_json('{"a": 1, "b": {"c": 2}}')
        {('a', 1), ('b', {'c': 2}), ('c', 2)}
    """
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError:
        return set()

    key_value_pairs = set()
    stack = [(data, "")]

    while stack:
        current_data, path = stack.pop()
        if isinstance(current_data, dict):
            for key, value in current_data.items():
                full_key = f"{path}.{key}" if path else key
                if isinstance(value, dict):
                    stack.append((value, full_key))
                elif isinstance(value, list):
                    stack.append((value, full_key))
                else:
                    if validate_parameter(full_key, compare_mode):
                        key_value_pairs.add((full_key, value))
        elif isinstance(current_data, list):
            for item in current_data:
                if isinstance(item, (dict, list)):
                    stack.append((item, path))
    return key_value_pairs


def extract_params_xml(xml_data, compare_mode="getparam"):
    """
    Extracts tags and their text values from an XML object and returns them as a set of tuples.

    Args:
        xml_data (str): XML-formatted string containing elements.

    Returns:
        set: A set of tuples containing the tags and their corresponding text values present in the XML object.

    Raises:
        Returns an empty set if ParseError occurs.

    Examples:
        >>> extract_params_xml('<root><child1><child2>value</child2></child1></root>')
        {('root', None), ('child1', None), ('child2', 'value')}
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return set()

    tag_value_pairs = set()
    stack = [root]

    while stack:
        current_element = stack.pop()
        if validate_parameter(current_element.tag, compare_mode):
            tag_value_pairs.add((current_element.tag, current_element.text))
        for child in current_element:
            stack.append(child)
    return tag_value_pairs


# Define valid characters for each mode based on RFCs
valid_chars_dict = {
    "header": set(
        chr(c) for c in range(33, 127) if chr(c) in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    ),
    "getparam": set(chr(c) for c in range(33, 127) if chr(c) not in ":/?#[]@!$&'()*+,;="),
    "postparam": set(chr(c) for c in range(33, 127) if chr(c) not in ":/?#[]@!$&'()*+,;="),
    "cookie": set(chr(c) for c in range(33, 127) if chr(c) not in '()<>@,;:"/[]?={} \t'),
}


def validate_parameter(param, compare_mode):
    compare_mode = compare_mode.lower()
    if len(param) > 100:
        return False
    if compare_mode not in valid_chars_dict:
        raise ValueError(f"Invalid compare_mode: {compare_mode}")
    allowed_chars = valid_chars_dict[compare_mode]
    return set(param).issubset(allowed_chars)


def extract_words(data, acronyms=True, wordninja=True, model=None, max_length=100, word_regexes=None):
    """Intelligently extracts words from given data.

    This function uses regular expressions and optionally wordninja to extract words
    from a given text string. Thanks to wordninja it can handle concatenated words intelligently.

    Args:
        data (str): The data from which words are to be extracted.
        acronyms (bool, optional): Whether to include acronyms. Defaults to True.
        wordninja (bool, optional): Whether to use the wordninja library to split concatenated words. Defaults to True.
        model (object, optional): A custom wordninja model for special types of data such as DNS names.
        max_length (int, optional): Maximum length for a word to be included. Defaults to 100.
        word_regexes (list, optional): A list of compiled regular expression objects for word extraction. Defaults to None.

    Returns:
        set: A set of extracted words.

    Examples:
        >>> extract_words('blacklanternsecurity')
        {'black', 'lantern', 'security', 'bls', 'blacklanternsecurity'}
    """
    import wordninja as _wordninja

    if word_regexes is None:
        word_regexes = bbot_regexes.word_regexes
    words = set()
    data = smart_decode(data)
    for r in word_regexes:
        for word in set(r.findall(data)):
            # blacklanternsecurity
            if len(word) <= max_length:
                words.add(word)

    # blacklanternsecurity --> ['black', 'lantern', 'security']
    # max_slice_length = 3
    for word in list(words):
        if wordninja:
            if model is None:
                model = _wordninja
            subwords = model.split(word)
            for subword in subwords:
                words.add(subword)
        # this section generates compound words
        # it is interesting but currently disabled the quality of its output doesn't quite justify its quantity
        # blacklanternsecurity --> ['black', 'lantern', 'security', 'blacklantern', 'lanternsecurity']
        # for s, e in combinations(range(len(subwords) + 1), 2):
        #    if e - s <= max_slice_length:
        #        subword_slice = "".join(subwords[s:e])
        #        words.add(subword_slice)
        # blacklanternsecurity --> bls
        if acronyms:
            if len(subwords) > 1:
                words.add("".join([c[0] for c in subwords if len(c) > 0]))

    return words


def closest_match(s, choices, n=1, cutoff=0.0):
    """Finds the closest matching strings from a list of choices based on a given string.

    This function uses the difflib library to find the closest matches to a given string `s` from a list of `choices`.
    It can return either the single best match or a list of the top `n` best matches.

    Args:
        s (str): The string for which to find the closest match.
        choices (list): A list of strings to compare against.
        n (int, optional): The number of best matches to return. Defaults to 1.
        cutoff (float, optional): A float value that defines the similarity threshold. Strings with similarity below this value are not considered. Defaults to 0.0.

    Returns:
        str or list: Either the closest matching string or a list of the `n` closest matching strings.

    Examples:
        >>> closest_match("asdf", ["asd", "fds"])
        'asd'
        >>> closest_match("asdf", ["asd", "fds", "asdff"], n=3)
        ['asdff', 'asd', 'fds']
    """
    import difflib

    matches = difflib.get_close_matches(s, choices, n=n, cutoff=cutoff)
    if not choices or not matches:
        return
    if n == 1:
        return matches[0]
    return matches


def get_closest_match(s, choices, msg=None):
    """Finds the closest match from a list of choices for a given string.

    This function is particularly useful for CLI applications where you want to validate flags or modules.

    Args:
        s (str): The string for which to find the closest match.
        choices (list): A list of strings to compare against.
        msg (str, optional): Additional message to prepend in the warning message. Defaults to None.
        loglevel (str, optional): The log level to use for the warning message. Defaults to "HUGEWARNING".
        exitcode (int, optional): The exit code to use when exiting the program. Defaults to 2.

    Examples:
        >>> get_closest_match("some_module", ["some_mod", "some_other_mod"], msg="module")
        # Output: Could not find module "some_module". Did you mean "some_mod"?
    """
    if msg is None:
        msg = ""
    else:
        msg += " "
    closest = closest_match(s, choices)
    return f'Could not find {msg}"{s}". Did you mean "{closest}"?'


def kill_children(parent_pid=None, sig=None):
    """
    Forgive me father for I have sinned
    """
    import psutil
    import signal

    if sig is None:
        sig = signal.SIGTERM

    try:
        parent = psutil.Process(parent_pid)
    except psutil.NoSuchProcess:
        log.debug(f"No such PID: {parent_pid}")
        return
    log.debug(f"Killing children of process ID {parent.pid}")
    children = parent.children(recursive=True)
    for child in children:
        log.debug(f"Killing child with PID {child.pid}")
        if child.name != "python":
            try:
                child.send_signal(sig)
            except psutil.NoSuchProcess:
                log.debug(f"No such PID: {child.pid}")
            except psutil.AccessDenied:
                log.debug(f"Error killing PID: {child.pid} - access denied")
    log.debug(f"Finished killing children of process ID {parent.pid}")


def str_or_file(s):
    """Reads a string or file and yields its content line-by-line.

    This function tries to open the given string `s` as a file and yields its lines.
    If it fails to open `s` as a file, it treats `s` as a regular string and yields it as is.

    Args:
        s (str): The string or file path to read.

    Yields:
        str: Either lines from the file or the original string.

    Examples:
        >>> list(str_or_file("file.txt"))
        ['file_line1', 'file_line2', 'file_line3']
        >>> list(str_or_file("not_a_file"))
        ['not_a_file']
    """
    try:
        with open(s, errors="ignore") as f:
            for line in f:
                yield line.rstrip("\r\n")
    except OSError:
        yield s


split_regex = re.compile(r"[\s,]")


def chain_lists(
    l,
    try_files=False,
    msg=None,
    remove_blank=True,
    validate=False,
    validate_chars='<>:"/\\|?*)',
):
    """Chains together list elements, allowing for entries separated by commas.

    This function takes a list `l` and flattens it by splitting its entries on commas.
    It also allows you to optionally open entries as files and add their contents to the list.

    The order of entries is preserved, and deduplication is performed automatically.

    Args:
        l (list): The list of strings to chain together.
        try_files (bool, optional): Whether to try to open entries as files. Defaults to False.
        msg (str, optional): An optional message to log when reading from a file. Defaults to None.
        remove_blank (bool, optional): Whether to remove blank entries from the list. Defaults to True.
        validate (bool, optional): Whether to perform validation for undesirable characters. Defaults to False.
        validate_chars (str, optional): When performing validation, what additional set of characters to block (blocks non-printable ascii automatically). Defaults to '<>:"/\\|?*)'

    Returns:
        list: The list of chained elements.

    Raises:
        ValueError: If the input string contains invalid characters, when enabled (off by default).

    Examples:
        >>> chain_lists(["a", "b,c,d"])
        ['a', 'b', 'c', 'd']

        >>> chain_lists(["a,file.txt", "c,d"], try_files=True)
        ['a', 'f_line1', 'f_line2', 'f_line3', 'c', 'd']
    """
    if isinstance(l, str):
        l = [l]
    final_list = dict()
    for entry in l:
        for s in split_regex.split(entry):
            f = s.strip()
            if validate:
                if any((c in validate_chars) or (ord(c) < 32 and c != " ") for c in f):
                    raise ValueError(f"Invalid character in string: {f}")
            f_path = Path(f).resolve()
            if try_files and f_path.is_file():
                if msg is not None:
                    new_msg = str(msg).format(filename=f_path)
                    log.info(new_msg)
                for line in str_or_file(f):
                    final_list[line] = None
            else:
                final_list[f] = None

    ret = list(final_list)
    if remove_blank:
        ret = [r for r in ret if r]
    return ret


def list_files(directory, filter=lambda x: True):
    """Lists files in a given directory that meet a specified filter condition.

    Args:
        directory (str): The directory where to list files.
        filter (callable, optional): A function to filter the files. Defaults to a lambda function that returns True for all files.

    Yields:
        Path: A Path object for each file that meets the filter condition.

    Examples:
        >>> list(list_files("/tmp/test"))
        [Path('/tmp/test/file1.py'), Path('/tmp/test/file2.txt')]

        >>> list(list_files("/tmp/test"), filter=lambda f: f.suffix == ".py")
        [Path('/tmp/test/file1.py')]
    """
    directory = Path(directory).resolve()
    if directory.is_dir():
        for file in directory.iterdir():
            if file.is_file() and filter(file):
                yield file


def rm_at_exit(path):
    """Registers a file to be automatically deleted when the program exits.

    Args:
        path (str or Path): The path to the file to be deleted upon program exit.

    Examples:
        >>> rm_at_exit("/tmp/test/file1.txt")
    """
    import atexit

    atexit.register(delete_file, path)


def delete_file(path):
    """Deletes a file at the given path.

    Args:
        path (str or Path): The path to the file to be deleted.

    Note:
        This function suppresses all exceptions to ensure that the program continues running even if the file could not be deleted.

    Examples:
        >>> delete_file("/tmp/test/file1.txt")
    """
    with suppress(Exception):
        Path(path).unlink(missing_ok=True)


def read_file(filename):
    """Reads a file line by line and yields each line without line breaks.

    Args:
        filename (str or Path): The path to the file to read.

    Yields:
        str: A line from the file without the trailing line break.

    Examples:
        >>> for line in read_file("/tmp/file.txt"):
        ...     print(line)
        file_line1
        file_line2
        file_line3
    """
    with open(filename, errors="ignore") as f:
        for line in f:
            yield line.rstrip("\r\n")


def gen_numbers(n, padding=2):
    """Generates numbers with variable padding and returns them as a set of strings.

    Args:
        n (int): The upper limit of numbers to generate, exclusive.
        padding (int, optional): The maximum number of digits to pad the numbers with. Defaults to 2.

    Returns:
        set: A set of string representations of numbers with varying degrees of padding.

    Examples:
        >>> gen_numbers(5)
        {'0', '00', '01', '02', '03', '04', '1', '2', '3', '4'}

        >>> gen_numbers(3, padding=3)
        {'0', '00', '000', '001', '002', '01', '02', '1', '2'}

        >>> gen_numbers(5, padding=1)
        {'0', '1', '2', '3', '4'}
    """
    results = set()
    for i in range(n):
        for p in range(1, padding + 1):
            results.add(str(i).zfill(p))
    return results


def make_netloc(host, port=None):
    """Constructs a network location string from a given host and port.

    Args:
        host (str): The hostname or IP address.
        port (int, optional): The port number. If None, the port is omitted.

    Returns:
        str: A network location string in the form 'host' or 'host:port'.

    Examples:
        >>> make_netloc("192.168.1.1", None)
        "192.168.1.1"

        >>> make_netloc("192.168.1.1", 443)
        "192.168.1.1:443"

        >>> make_netloc("evilcorp.com", 80)
        "evilcorp.com:80"

        >>> make_netloc("dead::beef", None)
        "[dead::beef]"

        >>> make_netloc("dead::beef", 443)
        "[dead::beef]:443"
    """
    if is_ip(host, version=6):
        host = f"[{host}]"
    if port is None:
        return str(host)
    return f"{host}:{port}"


def which(*executables):
    """Finds the full path of the first available executable from a list of executables.

    Args:
        *executables (str): One or more executable names to search for.

    Returns:
        str: The full path of the first available executable, or None if none are found.

    Examples:
        >>> which("python", "python3")
        "/usr/bin/python"
    """
    import shutil

    for e in executables:
        location = shutil.which(e)
        if location:
            return location


def search_dict_by_key(key, d):
    """Search a nested dictionary or list of dictionaries by a key and yield all matching values.

    Args:
        key (str): The key to search for.
        d (Union[dict, list]): The dictionary or list of dictionaries to search.

    Yields:
        Any: Yields all values that match the provided key.

    Examples:
        >>> d = {'a': 1, 'b': {'c': 2, 'a': 3}, 'd': [{'a': 4}, {'e': 5}]}
        >>> list(search_dict_by_key('a', d))
        [1, 3, 4]
    """
    if isinstance(d, dict):
        if key in d:
            yield d[key]
        for k, v in d.items():
            yield from search_dict_by_key(key, v)
    elif isinstance(d, list):
        for v in d:
            yield from search_dict_by_key(key, v)


def search_format_dict(d, **kwargs):
    """Recursively format string values in a dictionary or list using the provided keyword arguments.

    Args:
        d (Union[dict, list, str]): The dictionary, list, or string to format.
        **kwargs: Arbitrary keyword arguments used for string formatting.

    Returns:
        Union[dict, list, str]: The formatted dictionary, list, or string.

    Examples:
        >>> search_format_dict({"test": "#{name} is awesome"}, name="keanu")
        {"test": "keanu is awesome"}
    """
    if isinstance(d, dict):
        return {k: search_format_dict(v, **kwargs) for k, v in d.items()}
    elif isinstance(d, list):
        return [search_format_dict(v, **kwargs) for v in d]
    elif isinstance(d, str):
        for find, replace in kwargs.items():
            find = "#{" + str(find) + "}"
            d = d.replace(find, replace)
    return d


def search_dict_values(d, *regexes):
    """Recursively search a dictionary's values based on provided regex patterns.

    Args:
        d (Union[dict, list, str]): The dictionary, list, or string to search.
        *regexes: Arbitrary number of compiled regex patterns.

    Returns:
        Generator: Yields matching values based on the provided regex patterns.

    Examples:
        >>> dict_to_search = {
        ...     "key1": {
        ...         "key2": [
        ...             {
        ...                 "key3": "A URL: https://www.evilcorp.com"
        ...             }
        ...         ]
        ...     }
        ... }
        >>> url_regexes = re.compile(r'https?://[^\\s<>"]+|www\\.[^\\s<>"]+')
        >>> list(search_dict_values(dict_to_search, url_regexes))
        ["https://www.evilcorp.com"]
    """

    results = set()
    if isinstance(d, str):
        for r in regexes:
            for match in r.finditer(d):
                result = match.group()
                h = hash(result)
                if h not in results:
                    results.add(h)
                    yield result
    elif isinstance(d, dict):
        for _, v in d.items():
            yield from search_dict_values(v, *regexes)
    elif isinstance(d, list):
        for v in d:
            yield from search_dict_values(v, *regexes)


def grouper(iterable, n):
    """
    Grouper groups an iterable into chunks of a given size.

    Args:
        iterable (iterable): The iterable to be chunked.
        n (int): The size of each chunk.

    Returns:
        iterator: An iterator that produces lists of elements from the original iterable, each of length `n` or less.

    Examples:
        >>> list(grouper('ABCDEFG', 3))
        [['A', 'B', 'C'], ['D', 'E', 'F'], ['G']]
    """
    from itertools import islice

    iterable = iter(iterable)
    return iter(lambda: list(islice(iterable, n)), [])


def split_list(alist, wanted_parts=2):
    """
    Splits a list into a specified number of approximately equal parts.

    Args:
        alist (list): The list to be split.
        wanted_parts (int): The number of parts to split the list into.

    Returns:
        list: A list of lists, each containing a portion of the original list.

    Examples:
        >>> split_list([1, 2, 3, 4, 5])
        [[1, 2], [3, 4, 5]]
    """
    length = len(alist)
    return [alist[i * length // wanted_parts : (i + 1) * length // wanted_parts] for i in range(wanted_parts)]


def mkdir(path, check_writable=True, raise_error=True):
    """
    Creates a directory and optionally checks if it's writable.

    Args:
        path (str or Path): The directory to create.
        check_writable (bool, optional): Whether to check if the directory is writable. Default is True.
        raise_error (bool, optional): Whether to raise an error if the directory creation fails. Default is True.

    Returns:
        bool: True if the directory is successfully created (and writable, if check_writable=True); otherwise False.

    Raises:
        DirectoryCreationError: Raised if the directory cannot be created and `raise_error=True`.

    Examples:
        >>> mkdir("/tmp/new_dir")
        True
        >>> mkdir("/restricted_dir", check_writable=False, raise_error=False)
        False
    """
    path = Path(path).resolve()
    touchfile = path / f".{rand_string()}"
    try:
        path.mkdir(exist_ok=True, parents=True)
        if check_writable:
            touchfile.touch()
        return True
    except Exception as e:
        if raise_error:
            raise errors.DirectoryCreationError(f"Failed to create directory at {path}: {e}")
    finally:
        with suppress(Exception):
            touchfile.unlink()
    return False


def make_date(d=None, microseconds=False):
    """
    Generates a string representation of the current date and time, with optional microsecond precision.

    Args:
        d (datetime, optional): A datetime object to convert. Defaults to the current date and time.
        microseconds (bool, optional): Whether to include microseconds. Defaults to False.

    Returns:
        str: A string representation of the date and time, formatted as YYYYMMDD_HHMM_SS or YYYYMMDD_HHMM_SSFFFFFF if microseconds are included.

    Examples:
        >>> make_date()
        "20220707_1325_50"
        >>> make_date(microseconds=True)
        "20220707_1330_35167617"
    """
    from datetime import datetime

    f = "%Y%m%d_%H%M_%S"
    if microseconds:
        f += "%f"
    if d is None:
        d = datetime.now()
    return d.strftime(f)


def error_and_exit(msg):
    print(f"\n[!!!] {msg}\n")
    sys.exit(2)


def get_file_extension(s):
    """
    Extracts the file extension from a given string representing a URL or file path.

    Args:
        s (str): The string from which to extract the file extension.

    Returns:
        str: The file extension, or an empty string if no extension is found.

    Examples:
        >>> get_file_extension("https://evilcorp.com/api/test.php")
        "php"
        >>> get_file_extension("/etc/test.conf")
        "conf"
        >>> get_file_extension("/etc/passwd")
        ""
    """
    s = str(s).lower().strip()
    rightmost_section = s.rsplit("/", 1)[-1]
    if "." in rightmost_section:
        extension = rightmost_section.rsplit(".", 1)[-1]
        return extension
    return ""


def backup_file(filename, max_backups=10):
    """
    Renames a file by appending an iteration number as a backup. Recursively renames
    files up to a specified maximum number of backups.

    Args:
        filename (str or pathlib.Path): The file to backup.
        max_backups (int, optional): The maximum number of backups to keep. Defaults to 10.

    Returns:
        pathlib.Path: The new backup filepath.

    Examples:
        >>> backup_file("/tmp/test.txt")
        PosixPath("/tmp/test.0.txt")
        >>> backup_file("/tmp/test.0.txt")
        PosixPath("/tmp/test.1.txt")
        >>> backup_file("/tmp/test.1.txt")
        PosixPath("/tmp/test.2.txt")
    """
    filename = Path(filename).resolve()
    suffixes = [s.strip(".") for s in filename.suffixes]
    iteration = 1
    with suppress(Exception):
        iteration = min(max_backups - 1, max(0, int(suffixes[0]))) + 1
        suffixes = suffixes[1:]
    stem = filename.stem.split(".")[0]
    destination = filename.parent / f"{stem}.{iteration}.{'.'.join(suffixes)}"
    if destination.exists() and iteration < max_backups:
        backup_file(destination)
    if filename.exists():
        filename.rename(destination)
    return destination


def latest_mtime(d):
    """Get the latest modified time of any file or sub-directory in a given directory.

    This function takes a directory path as an argument and returns the latest modified time
    of any contained file or directory, recursively. It's useful for sorting directories by
    modified time for cleanup or other purposes.

    Args:
        d (str or Path): The directory path to search for the latest modified time.

    Returns:
        float: The latest modified time in Unix timestamp format.

    Examples:
        >>> latest_mtime("~/.bbot/scans/mushy_susan")
        1659016928.2848816
    """
    d = Path(d).resolve()
    mtimes = [d.lstat().st_mtime]
    if d.is_dir():
        to_list = d.glob("**/*")
    else:
        to_list = [d]
    for e in to_list:
        mtimes.append(e.lstat().st_mtime)
    return max(mtimes)


def filesize(f):
    """Get the file size of a given file.

    This function takes a file path as an argument and returns its size in bytes. If the path
    does not point to a file, the function returns 0.

    Args:
        f (str or Path): The file path for which to get the size.

    Returns:
        int: The size of the file in bytes, or 0 if the path does not point to a file.

    Examples:
        >>> filesize("/path/to/file.txt")
        1024
    """
    f = Path(f)
    if f.is_file():
        return f.stat().st_size
    return 0


def rm_rf(f):
    """Recursively delete a directory

    Args:
        f (str or Path): The directory path to delete.

    Examples:
        >>> rm_rf("/tmp/httpx98323849")
    """
    import shutil

    shutil.rmtree(f)


def clean_old(d, keep=10, filter=lambda x: True, key=latest_mtime, reverse=True, raise_error=False):
    """Clean up old files and directories within a given directory based on various filtering and sorting options.

    This function removes the oldest files and directories in the provided directory 'd' that exceed a specified
    threshold ('keep'). The items to be deleted can be filtered using a lambda function 'filter', and they are
    sorted by a key function, defaulting to latest modification time.

    Args:
        d (str or Path): The directory path to clean up.
        keep (int): The number of items to keep. Ones beyond this count will be removed.
        filter (Callable): A lambda function for filtering which files or directories to consider.
                           Defaults to a lambda function that returns True for all.
        key (Callable): A function to sort the files and directories. Defaults to latest modification time.
        reverse (bool): Whether to reverse the order of sorted items before removing. Defaults to True.
        raise_error (bool): Whether to raise an error if directory deletion fails. Defaults to False.

    Examples:
        >>> clean_old("~/.bbot/scans", filter=lambda x: x.is_dir() and scan_name_regex.match(x.name))
    """
    d = Path(d)
    if not d.is_dir():
        return
    paths = [x for x in d.iterdir() if filter(x)]
    paths.sort(key=key, reverse=reverse)
    for path in paths[keep:]:
        try:
            log.debug(f"Removing {path}")
            rm_rf(path)
        except Exception as e:
            msg = f"Failed to delete directory: {path}, {e}"
            if raise_error:
                raise errors.DirectoryDeletionError()
            log.warning(msg)


def extract_emails(s):
    """
    Extract email addresses from a body of text

    This function takes in a string and yields all email addresses found in it.
    The emails are converted to lower case before yielding. It utilizes
    regular expressions for email pattern matching.

    Args:
        s (str): The input string from which to extract email addresses.

    Yields:
        str: Yields email addresses found in the input string, in lower case.

    Examples:
        >>> list(extract_emails("Contact us at info@evilcorp.com and support@evilcorp.com"))
        ['info@evilcorp.com', 'support@evilcorp.com']
    """
    for email in bbot_regexes.email_regex.findall(smart_decode(s)):
        yield email.lower()


def extract_host(s):
    """
    Attempts to find and extract the host portion of a string.

    Args:
        s (str): The string from which to extract the host.

    Returns:
        tuple: A tuple containing three strings:
               (hostname (None if not found), string_before_hostname, string_after_hostname).

    Examples:
        >>> extract_host("evilcorp.com:80")
        ("evilcorp.com", "", ":80")

        >>> extract_host("http://evilcorp.com:80/asdf.php?a=b")
        ("evilcorp.com", "http://", ":80/asdf.php?a=b")

        >>> extract_host("bob@evilcorp.com")
        ("evilcorp.com", "bob@", "")

        >>> extract_host("[dead::beef]:22")
        ("dead::beef", "[", "]:22")

        >>> extract_host("ftp://username:password@my-ftp.com/my-file.csv")
        (
            "my-ftp.com",
            "ftp://username:password@",
            "/my-file.csv",
        )
    """
    s = smart_decode(s)
    match = bbot_regexes.extract_host_regex.search(s)

    if match:
        hostname = match.group(1)
        before = s[: match.start(1)]
        after = s[match.end(1) :]
        host, port = split_host_port(hostname)
        netloc = make_netloc(host, port)
        if netloc != hostname:
            # invalid host / port
            return (None, s, "")
        if host is not None:
            if port is not None:
                after = f":{port}{after}"
            if is_ip(host, version=6) and hostname.startswith("["):
                before = f"{before}["
                after = f"]{after}"
            hostname = str(host)
        return (hostname, before, after)

    return (None, s, "")


def smart_encode_punycode(text: str) -> str:
    """
    ドメイン.テスト --> xn--eckwd4c7c.xn--zckzah
    """
    import idna

    host, before, after = extract_host(text)
    if host is None:
        return text

    try:
        host = idna.encode(host).decode(errors="ignore")
    except UnicodeError:
        pass  # If encoding fails, leave the host as it is

    return f"{before}{host}{after}"


def smart_decode_punycode(text: str) -> str:
    """
    xn--eckwd4c7c.xn--zckzah --> ドメイン.テスト
    """
    import idna

    host, before, after = extract_host(text)
    if host is None:
        return text

    try:
        host = idna.decode(host)
    except UnicodeError:
        pass  # If decoding fails, leave the host as it is

    return f"{before}{host}{after}"


def can_sudo_without_password():
    """Check if the current user has passwordless sudo access.

    This function checks whether the current user can use sudo without entering a password.
    It runs a command with sudo and checks the return code to determine this.

    Returns:
        bool: True if the current user can use sudo without a password, False otherwise.

    Examples:
        >>> can_sudo_without_password()
        True
    """
    if os.geteuid() != 0:
        env = dict(os.environ)
        env["SUDO_ASKPASS"] = "/bin/false"
        try:
            sp.run(["sudo", "-K"], stderr=sp.DEVNULL, stdout=sp.DEVNULL, check=True, env=env)
            sp.run(["sudo", "-An", "/bin/true"], stderr=sp.DEVNULL, stdout=sp.DEVNULL, check=True, env=env)
        except sp.CalledProcessError:
            return False
    return True


def verify_sudo_password(sudo_pass):
    """Verify if the given sudo password is correct.

    This function checks whether the sudo password provided is valid for the current user.
    It runs a command with sudo, feeding in the password via stdin, and checks the return code.

    Args:
        sudo_pass (str): The sudo password to verify.

    Returns:
        bool: True if the sudo password is correct, False otherwise.

    Examples:
        >>> verify_sudo_password("mysecretpassword")
        True
    """
    try:
        sp.run(
            ["sudo", "-S", "-k", "true"],
            input=smart_encode(sudo_pass),
            stderr=sp.DEVNULL,
            stdout=sp.DEVNULL,
            check=True,
        )
    except sp.CalledProcessError:
        return False
    return True


def make_table(rows, header, **kwargs):
    """Generate a formatted table from the given rows and headers.

    This function uses the `tabulate` package to generate a table with formatting options.
    It can accept various input formats and table styles, which can be customized using optional arguments.

    Args:
        *args: Positional arguments to be passed to `tabulate.tabulate`.
        **kwargs: Keyword arguments to customize table formatting.
            - tablefmt (str, optional): Table format. Default is 'grid'.
            - disable_numparse (bool, optional): Disable automatic number parsing. Default is True.
            - maxcolwidths (int, optional): Maximum column width. Default is 40.

    Returns:
        str: A string representing the formatted table.

    Examples:
        >>> print(make_table([["row1", "row1"], ["row2", "row2"]], ["header1", "header2"]))
        +-----------+-----------+
        | header1   | header2   |
        +===========+===========+
        | row1      | row1      |
        +-----------+-----------+
        | row2      | row2      |
        +-----------+-----------+
    """
    from tabulate import tabulate

    # fix IndexError: list index out of range
    if not rows:
        rows = [[]]
    tablefmt = os.environ.get("BBOT_TABLE_FORMAT", None)
    defaults = {"tablefmt": "grid", "disable_numparse": True, "maxcolwidths": None}
    if tablefmt is None:
        defaults.update({"maxcolwidths": 40})
    else:
        defaults.update({"tablefmt": tablefmt})
    for k, v in defaults.items():
        if k not in kwargs:
            kwargs[k] = v
    # don't wrap columns in markdown
    if tablefmt in ("github", "markdown"):
        kwargs.pop("maxcolwidths")
        # escape problematic markdown characters in rows

        def markdown_escape(s):
            return str(s).replace("|", "&#124;")

        rows = [[markdown_escape(f) for f in row] for row in rows]
        header = [markdown_escape(h) for h in header]
    return tabulate(rows, header, **kwargs)


def human_timedelta(d):
    """Convert a TimeDelta object into a human-readable string.

    This function takes a datetime.timedelta object and converts it into a string format that
    is easier to read and understand.

    Args:
        d (datetime.timedelta): The TimeDelta object to convert.

    Returns:
        str: A string representation of the TimeDelta object in human-readable form.

    Examples:
        >>> from datetime import datetime
        >>>
        >>> start_time = datetime.now()
        >>> end_time = datetime.now()
        >>> elapsed_time = end_time - start_time
        >>> human_timedelta(elapsed_time)
        '2 hours, 30 minutes, 15 seconds'
    """
    hours, remainder = divmod(d.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    result = []
    if hours:
        result.append(f"{hours:,} hour" + ("s" if hours > 1 else ""))
    if minutes:
        result.append(f"{minutes:,} minute" + ("s" if minutes > 1 else ""))
    if seconds:
        result.append(f"{seconds:,} second" + ("s" if seconds > 1 else ""))
    ret = ", ".join(result)
    if not ret:
        ret = "0 seconds"
    return ret


def bytes_to_human(_bytes):
    """Convert a bytes size to a human-readable string.

    This function converts a numeric bytes value into a human-readable string format, complete
    with the appropriate unit symbol (B, KB, MB, GB, etc.).

    Args:
        _bytes (int): The number of bytes to convert.

    Returns:
        str: A string representing the number of bytes in a more readable format, rounded to two
             decimal places.

    Examples:
        >>> bytes_to_human(1234129384)
        '1.15GB'
    """
    sizes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"]
    units = {}
    for count, size in enumerate(sizes):
        units[size] = pow(1024, count)
    for size in sizes:
        if abs(_bytes) < 1024.0:
            if size == sizes[0]:
                _bytes = str(int(_bytes))
            else:
                _bytes = f"{_bytes:.2f}"
            return f"{_bytes}{size}"
        _bytes /= 1024
    raise ValueError(f'Unable to convert "{_bytes}" to human filesize')


filesize_regex = re.compile(r"(?P<num>[0-9\.]+)[\s]*(?P<char>[a-z])", re.I)


def human_to_bytes(filesize):
    """Convert a human-readable file size string to its bytes equivalent.

    This function takes a human-readable file size string, such as "2.5GB", and converts it
    to its equivalent number of bytes.

    Args:
        filesize (str or int): The human-readable file size string or integer bytes value to convert.

    Returns:
        int: The number of bytes equivalent to the input human-readable file size.

    Raises:
        ValueError: If the input string cannot be converted to bytes.

    Examples:
        >>> human_to_bytes("23.23gb")
        24943022571
    """
    if isinstance(filesize, int):
        return filesize
    sizes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"]
    units = {}
    for count, size in enumerate(sizes):
        size_increment = pow(1024, count)
        units[size] = size_increment
        if len(size) == 2:
            units[size[0]] = size_increment
    match = filesize_regex.match(filesize)
    try:
        if match:
            num, size = match.groups()
            size = size.upper()
            size_increment = units[size]
            return int(float(num) * size_increment)
    except KeyError:
        pass
    raise ValueError(f'Unable to convert filesize "{filesize}" to bytes')


def integer_to_ordinal(n):
    """
    Convert an integer to its ordinal representation.

    Args:
        n (int): The integer to convert.

    Returns:
        str: The ordinal representation of the integer.

    Examples:
        >>> integer_to_ordinal(1)
        '1st'
        >>> integer_to_ordinal(2)
        '2nd'
        >>> integer_to_ordinal(3)
        '3rd'
        >>> integer_to_ordinal(11)
        '11th'
        >>> integer_to_ordinal(21)
        '21st'
        >>> integer_to_ordinal(101)
        '101st'
    """
    # Check the last digit
    last_digit = n % 10
    # Check the last two digits for special cases (11th, 12th, 13th)
    last_two_digits = n % 100

    if 10 <= last_two_digits <= 20:
        suffix = "th"
    else:
        if last_digit == 1:
            suffix = "st"
        elif last_digit == 2:
            suffix = "nd"
        elif last_digit == 3:
            suffix = "rd"
        else:
            suffix = "th"

    return f"{n}{suffix}"


def cpu_architecture():
    """Return the CPU architecture of the current system.

    This function fetches and returns the architecture type of the CPU where the code is being executed.
    It maps common identifiers like "x86_64" to more general types like "amd64".

    Returns:
        str: A string representing the CPU architecture, such as "amd64", "armv7", or "arm64".

    Examples:
        >>> cpu_architecture()
        'amd64'
    """
    import platform

    uname = platform.uname()
    arch = uname.machine.lower()
    if arch.startswith("aarch"):
        return "arm64"
    elif arch == "x86_64":
        return "amd64"
    return arch


def os_platform():
    """Return the OS platform of the current system.

    This function fetches and returns the OS type where the code is being executed.
    It converts the platform identifier to lowercase.

    Returns:
        str: A string representing the OS platform, such as "linux", "darwin", or "windows".

    Examples:
        >>> os_platform()
        'linux'
    """
    import platform

    return platform.system().lower()


def os_platform_friendly():
    """Return a human-friendly OS platform string, suitable for golang release binaries.

    This function fetches the OS platform and modifies it to a more human-readable format if necessary.
    Specifically, it changes "darwin" to "macOS".

    Returns:
        str: A string representing the human-friendly OS platform, such as "macOS", "linux", or "windows".

    Examples:
        >>> os_platform_friendly()
        'macOS'
    """
    p = os_platform()
    if p == "darwin":
        return "macOS"
    return p


tag_filter_regex = re.compile(r"[^a-z0-9]+")


def tagify(s, delimiter=None, maxlen=None):
    """Sanitize a string into a tag-friendly format.

    Converts a given string to lowercase and replaces all characters not matching
    [a-z0-9] with hyphens. Optionally truncates the result to 'maxlen' characters.

    Args:
        s (str): The input string to sanitize.
        maxlen (int, optional): The maximum length for the tag. Defaults to None.

    Returns:
        str: A sanitized, tag-friendly string.

    Examples:
        >>> tagify("HTTP Web Title")
        'http-web-title'
        >>> tagify("HTTP Web Title", maxlen=8)
        'http-web'
    """
    if delimiter is None:
        delimiter = "-"
    ret = str(s).lower()
    return tag_filter_regex.sub(delimiter, ret)[:maxlen].strip(delimiter)


def memory_status():
    """Return statistics on system memory consumption.

    The function returns a `psutil` named tuple that contains statistics on
    system virtual memory usage, such as total memory, used memory, available
    memory, and more.

    Returns:
        psutil._pslinux.svmem: A named tuple representing various statistics
            about system virtual memory usage.

    Examples:
        >>> mem = memory_status()
        >>> mem.available
        13195399168

        >>> mem = memory_status()
        >>> mem.percent
        79.0
    """
    import psutil

    return psutil.virtual_memory()


def swap_status():
    """Return statistics on swap memory consumption.

    The function returns a `psutil` named tuple that contains statistics on
    system swap memory usage, such as total swap, used swap, free swap, and more.

    Returns:
        psutil._common.sswap: A named tuple representing various statistics
            about system swap memory usage.

    Examples:
        >>> swap = swap_status()
        >>> swap.total
        4294967296

        >>> swap = swap_status()
        >>> swap.used
        2097152
    """
    import psutil

    return psutil.swap_memory()


def get_size(obj, max_depth=5, seen=None):
    """
    Roughly estimate the memory footprint of a Python object using recursion.

    Parameters:
        obj (any): The object whose size is to be determined.
        max_depth (int, optional): Maximum depth to which nested objects will be inspected. Defaults to 5.
        seen (set, optional): Objects that have already been accounted for, to avoid loops.

    Returns:
        int: Approximate memory footprint of the object in bytes.

    Examples:
        >>> get_size(my_list)
        4200

        >>> get_size(my_dict, max_depth=3)
        8400
    """
    from collections.abc import Mapping

    # If seen is not provided, initialize an empty set
    if seen is None:
        seen = set()
    # Get the id of the object
    obj_id = id(obj)
    # Decrease the maximum depth for the next recursion
    new_max_depth = max_depth - 1
    # If the object has already been seen or we've reached the maximum recursion depth, return 0
    if obj_id in seen or new_max_depth <= 0:
        return 0
    # Get the size of the object
    size = sys.getsizeof(obj)
    # Add the object's id to the set of seen objects
    seen.add(obj_id)
    # If the object has a __dict__ attribute, we want to measure its size
    if hasattr(obj, "__dict__"):
        # Iterate over the Method Resolution Order (MRO) of the class of the object
        for cls in obj.__class__.__mro__:
            # If the class's __dict__ contains a __dict__ key
            if "__dict__" in cls.__dict__:
                for k, v in obj.__dict__.items():
                    size += get_size(k, new_max_depth, seen)
                    size += get_size(v, new_max_depth, seen)
                break
    # If the object is a mapping (like a dictionary), we want to measure the size of its items
    if isinstance(obj, Mapping):
        with suppress(StopIteration):
            k, v = next(iter(obj.items()))
            size += (get_size(k, new_max_depth, seen) + get_size(v, new_max_depth, seen)) * len(obj)
    # If the object is a container (like a list or tuple) but not a string or bytes-like object
    elif isinstance(obj, (list, tuple, set)):
        with suppress(StopIteration):
            size += get_size(next(iter(obj)), new_max_depth, seen) * len(obj)
    # If the object has __slots__, we want to measure the size of the attributes in __slots__
    if hasattr(obj, "__slots__"):
        size += sum(get_size(getattr(obj, s), new_max_depth, seen) for s in obj.__slots__ if hasattr(obj, s))
    return size


def is_file(f):
    """
    Check if a path points to a file.

    Parameters:
        f (str): Path to the file.

    Returns:
        bool: True if the path is a file, False otherwise.

    Examples:
        >>> is_file("/etc/passwd")
        True

        >>> is_file("/nonexistent")
        False
    """
    with suppress(Exception):
        return Path(f).is_file()
    return False


def cloudcheck(ip):
    """
    Check whether an IP address belongs to a cloud provider and returns the provider name, type, and subnet.

    Args:
        ip (str): The IP address to check.

    Returns:
        tuple: A tuple containing provider name (str), provider type (str), and subnet (IPv4Network).

    Examples:
        >>> cloudcheck("168.62.20.37")
        ('Azure', 'cloud', IPv4Network('168.62.0.0/19'))
    """
    import cloudcheck as _cloudcheck

    return _cloudcheck.check(ip)


def is_async_function(f):
    """
    Check if a given function is an asynchronous function.

    Args:
        f (function): The function to check.

    Returns:
        bool: True if the function is asynchronous, False otherwise.

    Examples:
        >>> async def foo():
        ...     pass
        >>> is_async_function(foo)
        True
    """
    import inspect

    return inspect.iscoroutinefunction(f)


async def execute_sync_or_async(callback, *args, **kwargs):
    """
    Execute a function or coroutine, handling either synchronous or asynchronous invocation.

    Args:
        callback (Union[Callable, Coroutine]): The function or coroutine to execute.
        *args: Variable-length argument list to pass to the callback.
        **kwargs: Arbitrary keyword arguments to pass to the callback.

    Returns:
        Any: The return value from the executed function or coroutine.

    Examples:
        >>> async def foo_async(x):
        ...     return x + 1
        >>> def foo_sync(x):
        ...     return x + 1

        >>> asyncio.run(execute_sync_or_async(foo_async, 1))
        2

        >>> asyncio.run(execute_sync_or_async(foo_sync, 1))
        2
    """
    if is_async_function(callback):
        return await callback(*args, **kwargs)
    else:
        return callback(*args, **kwargs)


def get_exception_chain(e):
    """
    Retrieves the full chain of exceptions leading to the given exception.

    Args:
        e (BaseException): The exception for which to get the chain.

    Returns:
        list[BaseException]: List of exceptions in the chain, from the given exception back to the root cause.

    Examples:
        >>> try:
        ...     raise ValueError("This is a value error")
        ... except ValueError as e:
        ...     exc_chain = get_exception_chain(e)
        ...     for exc in exc_chain:
        ...         print(exc)
        This is a value error
    """
    exception_chain = []
    current_exception = e
    while current_exception is not None:
        exception_chain.append(current_exception)
        current_exception = getattr(current_exception, "__context__", None)
    return exception_chain


def in_exception_chain(e, exc_types):
    """
    Given an Exception and a list of Exception types, returns whether any of the specified types are contained anywhere in the Exception chain.

    Args:
        e (BaseException): The exception to check
        exc_types (list[Exception]): Exception types to consider intentional cancellations. Default is KeyboardInterrupt

    Returns:
        bool: Whether the error is the result of an intentional cancellaion

    Examples:
        >>> try:
        ...     raise ValueError("This is a value error")
        ... except Exception as e:
        ...     if not in_exception_chain(e, (KeyboardInterrupt, asyncio.CancelledError)):
        ...         raise
    """
    return any([isinstance(_, exc_types) for _ in get_exception_chain(e)])


def get_traceback_details(e):
    """
    Retrieves detailed information from the traceback of an exception.

    Args:
        e (BaseException): The exception for which to get traceback details.

    Returns:
        tuple: A tuple containing filename (str), line number (int), and function name (str) where the exception was raised.

    Examples:
        >>> try:
        ...     raise ValueError("This is a value error")
        ... except ValueError as e:
        ...     filename, lineno, funcname = get_traceback_details(e)
        ...     print(f"File: {filename}, Line: {lineno}, Function: {funcname}")
        File: <stdin>, Line: 2, Function: <module>
    """
    import traceback

    tb = traceback.extract_tb(e.__traceback__)
    last_frame = tb[-1]  # Get the last frame in the traceback (the one where the exception was raised)
    filename = last_frame.filename
    lineno = last_frame.lineno
    funcname = last_frame.name
    return filename, lineno, funcname


async def cancel_tasks(tasks, ignore_errors=True):
    """
    Asynchronously cancels a list of asyncio tasks.

    Args:
        tasks (list[Task]): A list of asyncio Task objects to cancel.
        ignore_errors (bool, optional): Whether to ignore errors other than asyncio.CancelledError. Defaults to True.

    Examples:
        >>> async def main():
        ...     task1 = asyncio.create_task(async_function1())
        ...     task2 = asyncio.create_task(async_function2())
        ...     await cancel_tasks([task1, task2])
        ...
        >>> asyncio.run(main())

    Note:
        This function will not cancel the current task that it is called from.
    """
    current_task = asyncio.current_task()
    tasks = [t for t in tasks if t != current_task]
    for task in tasks:
        # log.debug(f"Cancelling task: {task}")
        task.cancel()
    if ignore_errors:
        for task in tasks:
            try:
                await task
            except BaseException as e:
                if not isinstance(e, asyncio.CancelledError):
                    import traceback

                    log.trace(traceback.format_exc())


def cancel_tasks_sync(tasks):
    """
    Synchronously cancels a list of asyncio tasks.

    Args:
        tasks (list[Task]): A list of asyncio Task objects to cancel.

    Examples:
        >>> loop = asyncio.get_event_loop()
        >>> task1 = loop.create_task(some_async_function1())
        >>> task2 = loop.create_task(some_async_function2())
        >>> cancel_tasks_sync([task1, task2])

    Note:
        This function will not cancel the current task from which it is called.
    """
    current_task = asyncio.current_task()
    for task in tasks:
        if task != current_task:
            # log.debug(f"Cancelling task: {task}")
            task.cancel()


def weighted_shuffle(items, weights):
    """
    Shuffles a list of items based on their corresponding weights.

    Args:
        items (list): The list of items to shuffle.
        weights (list): The list of weights corresponding to each item.

    Returns:
        list: A new list containing the shuffled items.

    Examples:
        >>> items = ['apple', 'banana', 'cherry']
        >>> weights = [0.4, 0.5, 0.1]
        >>> weighted_shuffle(items, weights)
        ['banana', 'apple', 'cherry']
        >>> weighted_shuffle(items, weights)
        ['apple', 'banana', 'cherry']
        >>> weighted_shuffle(items, weights)
        ['apple', 'banana', 'cherry']
        >>> weighted_shuffle(items, weights)
        ['banana', 'apple', 'cherry']

    Note:
        The sum of all weights does not have to be 1. They will be normalized internally.
    """
    # Create a list of tuples where each tuple is (item, weight)
    pool = list(zip(items, weights))

    shuffled_items = []

    # While there are still items to be chosen...
    while pool:
        # Normalize weights
        total = sum(weight for item, weight in pool)
        weights = [weight / total for item, weight in pool]

        # Choose an index based on weight
        chosen_index = random.choices(range(len(pool)), weights=weights, k=1)[0]

        # Add the chosen item to the shuffled list
        chosen_item, chosen_weight = pool.pop(chosen_index)
        shuffled_items.append(chosen_item)

    return shuffled_items


def parse_port_string(port_string):
    """
    Parses a string containing ports and port ranges into a list of individual ports.

    Args:
        port_string (str): The string containing individual ports and port ranges separated by commas.

    Returns:
        list: A list of individual ports parsed from the input string.

    Raises:
        ValueError: If the input string contains invalid ports or port ranges.

    Examples:
        >>> parse_port_string("22,80,1000-1002")
        [22, 80, 1000, 1001, 1002]

        >>> parse_port_string("1-2,3-5")
        [1, 2, 3, 4, 5]

        >>> parse_port_string("invalid")
        ValueError: Invalid port or port range: invalid
    """
    elements = str(port_string).split(",")
    ports = []

    for element in elements:
        if element.isdigit():
            port = int(element)
            if 1 <= port <= 65535:
                ports.append(port)
            else:
                raise ValueError(f"Invalid port: {element}")
        elif "-" in element:
            range_parts = element.split("-")
            if len(range_parts) != 2 or not all(part.isdigit() for part in range_parts):
                raise ValueError(f"Invalid port or port range: {element}")
            start, end = map(int, range_parts)
            if not (1 <= start < end <= 65535):
                raise ValueError(f"Invalid port range: {element}")
            ports.extend(range(start, end + 1))
        else:
            raise ValueError(f"Invalid port or port range: {element}")

    return ports


async def as_completed(coros):
    """
    Async generator that yields completed Tasks as they are completed.

    Args:
        coros (iterable): An iterable of coroutine objects or asyncio Tasks.

    Yields:
        asyncio.Task: A Task object that has completed its execution.

    Examples:
        >>> async def main():
        ...     async for task in as_completed([coro1(), coro2(), coro3()]):
        ...         result = task.result()
        ...         print(f'Task completed with result: {result}')

        >>> asyncio.run(main())
    """
    tasks = {coro if isinstance(coro, asyncio.Task) else asyncio.create_task(coro): coro for coro in coros}
    while tasks:
        done, _ = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            tasks.pop(task)
            yield task


def clean_dns_record(record):
    """
    Cleans and formats a given DNS record for further processing.

    This static method converts the DNS record to text format if it's not already a string.
    It also removes any trailing dots and converts the record to lowercase.

    Args:
        record (str or dns.rdata.Rdata): The DNS record to clean.

    Returns:
        str: The cleaned and formatted DNS record.

    Examples:
        >>> clean_dns_record('www.evilcorp.com.')
        'www.evilcorp.com'

        >>> from dns.rrset import from_text
        >>> record = from_text('www.evilcorp.com', 3600, 'IN', 'A', '1.2.3.4')[0]
        >>> clean_dns_record(record)
        '1.2.3.4'
    """
    if not isinstance(record, str):
        record = str(record.to_text())
    return str(record).rstrip(".").lower()


def truncate_filename(file_path, max_length=255):
    """
    Truncate the filename while preserving the file extension to ensure the total path length does not exceed the maximum length.

    Args:
        file_path (str): The original file path.
        max_length (int): The maximum allowed length for the total path. Default is 255.

    Returns:
        pathlib.Path: A new Path object with the truncated filename.

    Raises:
        ValueError: If the directory path is too long to accommodate any filename within the limit.

    Example:
        >>> truncate_filename('/path/to/example_long_filename.txt', 20)
        PosixPath('/path/to/example.txt')
    """
    p = Path(file_path)
    directory, stem, suffix = p.parent, p.stem, p.suffix

    max_filename_length = max_length - len(str(directory)) - len(suffix) - 1  # 1 for the '/' separator

    if max_filename_length <= 0:
        raise ValueError("The directory path is too long to accommodate any filename within the limit.")

    if len(stem) > max_filename_length:
        truncated_stem = stem[:max_filename_length]
    else:
        truncated_stem = stem

    new_path = directory / (truncated_stem + suffix)
    return new_path


def get_keys_in_dot_syntax(config):
    """Retrieve all keys in an OmegaConf configuration in dot notation.

    This function converts an OmegaConf configuration into a list of keys
    represented in dot notation.

    Args:
        config (DictConfig): The OmegaConf configuration object.

    Returns:
        List[str]: A list of keys in dot notation.

    Examples:
        >>> config = OmegaConf.create({
        ...     "web": {
        ...         "test": True
        ...     },
        ...     "db": {
        ...         "host": "localhost",
        ...         "port": 5432
        ...     }
        ... })
        >>> get_keys_in_dot_syntax(config)
        ['web.test', 'db.host', 'db.port']
    """
    from omegaconf import OmegaConf

    container = OmegaConf.to_container(config, resolve=True)
    keys = []

    def recursive_keys(d, parent_key=""):
        for k, v in d.items():
            full_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                recursive_keys(v, full_key)
            else:
                keys.append(full_key)

    recursive_keys(container)
    return keys


def filter_dict(d, *key_names, fuzzy=False, exclude_keys=None, _prev_key=None):
    """
    Recursively filter a dictionary based on key names.

    Args:
        d (dict): The input dictionary.
        *key_names: Names of keys to filter for.
        fuzzy (bool): Whether to perform fuzzy matching on keys.
        exclude_keys (list, None): List of keys to be excluded from the final dict.
        _prev_key (str, None): For internal recursive use; the previous key in the hierarchy.

    Returns:
        dict: A dictionary containing only the keys specified in key_names.

    Examples:
        >>> filter_dict({"key1": "test", "key2": "asdf"}, "key2")
        {"key2": "asdf"}
        >>> filter_dict({"key1": "test", "key2": {"key3": "asdf"}}, "key1", "key3", exclude_keys="key2")
        {'key1': 'test'}
    """
    if exclude_keys is None:
        exclude_keys = []
    if isinstance(exclude_keys, str):
        exclude_keys = [exclude_keys]
    ret = {}
    if isinstance(d, dict):
        for key in d:
            if key in key_names or (fuzzy and any(k in key for k in key_names)):
                if not any(k in exclude_keys for k in [key, _prev_key]):
                    ret[key] = copy.deepcopy(d[key])
            elif isinstance(d[key], list) or isinstance(d[key], dict):
                child = filter_dict(d[key], *key_names, fuzzy=fuzzy, _prev_key=key, exclude_keys=exclude_keys)
                if child:
                    ret[key] = child
    return ret


def clean_dict(d, *key_names, fuzzy=False, exclude_keys=None, _prev_key=None):
    """
    Recursively clean unwanted keys from a dictionary.
    Useful for removing secrets from a config.

    Args:
        d (dict): The input dictionary.
        *key_names: Names of keys to remove.
        fuzzy (bool): Whether to perform fuzzy matching on keys.
        exclude_keys (list, None): List of keys to be excluded from removal.
        _prev_key (str, None): For internal recursive use; the previous key in the hierarchy.

    Returns:
        dict: A dictionary cleaned of the keys specified in key_names.

    """
    if exclude_keys is None:
        exclude_keys = []
    if isinstance(exclude_keys, str):
        exclude_keys = [exclude_keys]
    d = copy.deepcopy(d)
    if isinstance(d, dict):
        for key, val in list(d.items()):
            if key in key_names or (fuzzy and any(k in key for k in key_names)):
                if _prev_key not in exclude_keys:
                    d.pop(key)
                    continue
            d[key] = clean_dict(val, *key_names, fuzzy=fuzzy, _prev_key=key, exclude_keys=exclude_keys)
    return d


top_ports_cache = None


def top_tcp_ports(n, as_string=False):
    """
    Returns the top *n* TCP ports as evaluated by nmap
    """
    top_ports_file = Path(__file__).parent.parent.parent / "wordlists" / "top_open_ports_nmap.txt"

    global top_ports_cache
    if top_ports_cache is None:
        # Read the open ports from the file
        with open(top_ports_file, "r") as f:
            top_ports_cache = [int(line.strip()) for line in f]

        # If n is greater than the length of the ports list, add remaining ports from range(1, 65536)
        unique_ports = set(top_ports_cache)
        top_ports_cache.extend([port for port in range(1, 65536) if port not in unique_ports])

    top_ports = top_ports_cache[:n]
    if as_string:
        return ",".join([str(s) for s in top_ports])
    return top_ports


class SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def safe_format(s, **kwargs):
    """
    Format string while ignoring unused keys (prevents KeyError)
    """
    return s.format_map(SafeDict(kwargs))
