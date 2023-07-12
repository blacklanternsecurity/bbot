import os
import re
import sys
import copy
import json
import atexit
import codecs
import psutil
import random
import shutil
import signal
import string
import asyncio
import difflib
import inspect
import logging
import platform
import ipaddress
import traceback
import subprocess as sp
from pathlib import Path
from itertools import islice
from datetime import datetime
from tabulate import tabulate
import wordninja as _wordninja
from contextlib import suppress
import cloudcheck as _cloudcheck
import tldextract as _tldextract
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from hashlib import sha1 as hashlib_sha1
from urllib.parse import urlparse, quote, unquote, urlunparse  # noqa F401
from asyncio import as_completed, create_task, sleep, wait_for  # noqa

from .url import *  # noqa F401
from . import regexes
from .. import errors
from .punycode import *  # noqa F401
from .logger import log_to_stderr
from .names_generator import random_name, names, adjectives  # noqa F401

log = logging.getLogger("bbot.core.helpers.misc")


def is_domain(d):
    """
    "evilcorp.co.uk" --> True
    "www.evilcorp.co.uk" --> False
    """
    d, _ = split_host_port(d)
    extracted = tldextract(d)
    if extracted.domain and not extracted.subdomain:
        return True
    return False


def is_subdomain(d):
    """
    "www.evilcorp.co.uk" --> True
    "evilcorp.co.uk" --> False
    """
    d, _ = split_host_port(d)
    extracted = tldextract(d)
    if extracted.domain and extracted.subdomain:
        return True
    return False


def is_ptr(d):
    """
    "wsc-11-22-33-44.evilcorp.com" --> True
    "www2.evilcorp.com" --> False
    """
    return bool(regexes.ptr_regex.search(str(d)))


def is_url(u):
    u = str(u)
    for r in regexes.event_type_regexes["URL"]:
        if r.match(u):
            return True
    return False


uri_regex = re.compile(r"^([a-z0-9]{2,20})://", re.I)


def is_uri(u, return_scheme=False):
    """
    is_uri("http://evilcorp.com") --> True
    is_uri("ftp://evilcorp.com") --> True
    is_uri("evilcorp.com") --> False
    is_uri("ftp://evilcorp.com", return_scheme=True) --> "ftp"
    """
    match = uri_regex.match(u)
    if return_scheme:
        if match:
            return match.groups()[0].lower()
        return ""
    return bool(match)


def split_host_port(d):
    """
    "evilcorp.com:443" --> ("evilcorp.com", 443)
    "192.168.1.1:443" --> (IPv4Address('192.168.1.1'), 443)
    "[dead::beef]:443" --> (IPv6Address('dead::beef'), 443)
    """
    if not "://" in d:
        d = f"d://{d}"
    parsed = urlparse(d)
    port = None
    host = None
    with suppress(ValueError):
        if parsed.port is None:
            if parsed.scheme in ("https", "wss"):
                port = 443
            elif parsed.scheme in ("http", "ws"):
                port = 80
        else:
            port = int(parsed.port)
    with suppress(ValueError):
        host = parsed.hostname
    return make_ip_type(host), port


def parent_domain(d):
    """
    "www.internal.evilcorp.co.uk" --> "internal.evilcorp.co.uk"
    "www.internal.evilcorp.co.uk:8080" --> "internal.evilcorp.co.uk:8080"
    "www.evilcorp.co.uk" --> "evilcorp.co.uk"
    "evilcorp.co.uk" --> "evilcorp.co.uk"
    """
    host, port = split_host_port(d)
    if is_subdomain(d):
        return make_netloc(".".join(str(host).split(".")[1:]), port)
    return d


def domain_parents(d, include_self=False):
    """
    "test.www.evilcorp.co.uk" --> ["www.evilcorp.co.uk", "evilcorp.co.uk"]
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


def parent_url(u):
    parsed = urlparse(u)
    path = Path(parsed.path)
    if path.parent == path:
        return None
    else:
        return urlunparse(parsed._replace(path=str(path.parent)))


def url_parents(u):
    """
    "http://www.evilcorp.co.uk/admin/tools/cmd.php" --> ["http://www.evilcorp.co.uk/admin/tools/","http://www.evilcorp.co.uk/admin/", "http://www.evilcorp.co.uk/"]
    """

    parent_list = set()
    while 1:
        parent = parent_url(u)
        if parent == None:
            return list(parent_list)
        else:
            parent_list.add(parent)
            u = parent


def tldextract(data):
    """
    "www.evilcorp.co.uk" --> ExtractResult(subdomain='www', domain='evilcorp', suffix='co.uk')
    """
    return _tldextract.extract(smart_decode(data))


def split_domain(hostname):
    """
    "www.internal.evilcorp.co.uk" --> ("www.internal", "evilcorp.co.uk")
    """
    parsed = tldextract(hostname)
    return (parsed.subdomain, parsed.registered_domain)


def domain_stem(domain):
    """
    An abbreviated representation of hostname that removes the TLD
        www.evilcorp.com --> www.evilcorp
    """
    parsed = tldextract(str(domain))
    return f".".join(parsed.subdomain.split(".") + parsed.domain.split(".")).strip(".")


def ip_network_parents(i, include_self=False):
    """
    "192.168.1.1" --> [192.168.1.0/31, 192.168.1.0/30 ... 128.0.0.0/1, 0.0.0.0/0]
    """
    net = ipaddress.ip_network(i, strict=False)
    for i in range(net.prefixlen - (0 if include_self else 1), -1, -1):
        yield ipaddress.ip_network(f"{net.network_address}/{i}", strict=False)


def is_port(p):
    p = str(p)
    return p and p.isdigit() and 0 <= int(p) <= 65535


def is_dns_name(d):
    if is_ip(d):
        return False
    d = smart_decode(d)
    if regexes.hostname_regex.match(d):
        return True
    if regexes.dns_name_regex.match(d):
        return True
    return False


def is_ip(d, version=None):
    """
    "192.168.1.1" --> True
    "bad::c0de" --> True
    "evilcorp.com" --> False
    """
    if type(d) in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        if version is None or version == d.version:
            return True
    try:
        ip = ipaddress.ip_address(d)
        if version is None or ip.version == version:
            return True
    except Exception:
        pass
    return False


def is_ip_type(i):
    """
    IPv6Address('dead::beef') --> True
    IPv4Network('192.168.1.0/24') --> True
    "192.168.1.0/24" --> False
    """
    return hasattr(i, "is_multicast")


def make_ip_type(s):
    """
    "dead::beef" --> IPv6Address('dead::beef')
    "192.168.1.0/24" --> IPv4Network('192.168.1.0/24')
    "evilcorp.com" --> "evilcorp.com"
    """
    # IP address
    with suppress(Exception):
        return ipaddress.ip_address(str(s).strip())
    # IP network
    with suppress(Exception):
        return ipaddress.ip_network(str(s).strip(), strict=False)
    return s


def host_in_host(host1, host2):
    """
    Is host1 included in host2?
        "www.evilcorp.com" in "evilcorp.com"? --> True
        "evilcorp.com" in "www.evilcorp.com"? --> False
        IPv6Address('dead::beef') in IPv6Network('dead::/64')? --> True
        IPv4Address('192.168.1.1') in IPv4Network('10.0.0.0/8')? --> False
    """

    if not host1 or not host2:
        return False

    # check if hosts are IP types
    host1_ip_type = is_ip_type(host1)
    host2_ip_type = is_ip_type(host2)
    # if both hosts are IP types
    if host1_ip_type and host2_ip_type:
        if not host1.version == host2.version:
            return False
        host1_net = ipaddress.ip_network(host1)
        host2_net = ipaddress.ip_network(host2)
        return host1_net.subnet_of(host2_net)

    # else hostnames
    elif not (host1_ip_type or host2_ip_type):
        host2_len = len(host2.split("."))
        host1_truncated = ".".join(host1.split(".")[-host2_len:])
        return host1_truncated == host2

    return False


def sha1(data):
    """
    sha1("asdf").hexdigest() --> "3da541559918a808c2402bba5012f6c60b27661c"
    """
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    return hashlib_sha1(smart_encode(data))


def smart_decode(data):
    """
    Turn data into a string without complaining about it
        b"asdf" --> "asdf"
        "asdf" --> "asdf"
    """
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore")
    else:
        return str(data)


def smart_encode(data):
    """
    Turn data into bytes without complaining about it
        "asdf" --> b"asdf"
    """
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8", errors="ignore")


encoded_regex = re.compile(r"%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\[ntrbv]")
backslash_regex = re.compile(r"(?P<slashes>\\+)(?P<char>[ntrvb])")


def recursive_decode(data, max_depth=5):
    """
    Encode double or triple-encoded strings
    """
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
        data = codecs.decode(data, "unicode_escape", errors="ignore")
    # Check if there's still URL-encoded or Unicode-escaped content
    if encoded_regex.search(data):
        # If yes, continue decoding
        return recursive_decode(data, max_depth=max_depth - 1)

    return data


rand_pool = string.ascii_lowercase
rand_pool_digits = rand_pool + string.digits


def rand_string(length=10, digits=True):
    """
    rand_string() --> "c4hp4i9jzx"
    rand_string(20) --> "ap4rsdtg5iw7ey7y3oa5"
    rand_string(30) --> "xdmyxtglqf0z3q8t46n430kesq68yu"
    """
    pool = rand_pool
    if digits:
        pool = rand_pool_digits
    return "".join([random.choice(pool) for _ in range(int(length))])


def extract_params_json(json_data):
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError:
        log.debug("Invalid JSON supplied. Returning empty list.")
        return set()

    keys = set()
    stack = [data]

    while stack:
        current_data = stack.pop()
        if isinstance(current_data, dict):
            for key, value in current_data.items():
                keys.add(key)
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(current_data, list):
            for item in current_data:
                if isinstance(item, (dict, list)):
                    stack.append(item)

    return keys


def extract_params_xml(xml_data):
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        log.debug("Invalid XML supplied. Returning empty list.")
        return set()

    tags = set()
    stack = [root]

    while stack:
        current_element = stack.pop()
        tags.add(current_element.tag)
        for child in current_element:
            stack.append(child)
    return tags


def extract_params_html(html_data):
    input_tag = regexes.input_tag_regex.findall(html_data)

    for i in input_tag:
        log.debug(f"FOUND PARAM ({i}) IN INPUT TAGS")
        yield i

    # check for jquery get parameters
    jquery_get = regexes.jquery_get_regex.findall(html_data)

    for i in jquery_get:
        log.debug(f"FOUND PARAM ({i}) IN JQUERY GET PARAMS")
        yield i

    # check for jquery post parameters
    jquery_post = regexes.jquery_post_regex.findall(html_data)
    if jquery_post:
        for i in jquery_post:
            for x in i.split(","):
                s = x.split(":")[0].rstrip()
                log.debug(f"FOUND PARAM ({s}) IN A JQUERY POST PARAMS")
                yield s

    a_tag = regexes.a_tag_regex.findall(html_data)
    for s in a_tag:
        log.debug(f"FOUND PARAM ({s}) IN A TAG GET PARAMS")
        yield s


def extract_words(data, acronyms=True, wordninja=True, model=None, max_length=100, word_regexes=None):
    """
    Intelligently extract words from given data
    Returns set() of extracted words
    """
    if word_regexes is None:
        word_regexes = regexes.word_regexes
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
    """
    Given a string and a list of choices, returns the best match

    closest_match("asdf", ["asd", "fds"]) --> "asd"
    closest_match("asdf", ["asd", "fds", "asdff"], n=3) --> ["asd", "asdff", "fds"]
    """
    matches = difflib.get_close_matches(s, choices, n=n, cutoff=cutoff)
    if not choices or not matches:
        return
    if n == 1:
        return matches[0]
    return matches


def match_and_exit(s, choices, msg=None, loglevel="HUGEWARNING", exitcode=2):
    """
    Return the closest match, warn, and exit
    """
    if msg is None:
        msg = ""
    else:
        msg += " "
    closest = closest_match(s, choices)
    log_to_stderr(f'Could not find {msg}"{s}". Did you mean "{closest}"?', level="HUGEWARNING")
    sys.exit(2)


def kill_children(parent_pid=None, sig=signal.SIGTERM):
    """
    Forgive me father for I have sinned
    """
    try:
        parent = psutil.Process(parent_pid)
    except psutil.NoSuchProcess:
        log.debug(f"No such PID: {parent_pid}")
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


def str_or_file(s):
    """
    "file.txt" --> ["file_line1", "file_line2", "file_line3"]
    "not_a_file" --> ["not_a_file"]
    """
    try:
        with open(s, errors="ignore") as f:
            for line in f:
                yield line.rstrip("\r\n")
    except OSError:
        yield s


def chain_lists(l, try_files=False, msg=None, remove_blank=True):
    """
    Chain together list, splitting entries on comma
        - Optionally try to open entries as files and add their contents to the list
        - Used for parsing a list of arguments that may include space and/or comma-separated values
        - ["a", "b,c,d"] --> ["a", "b", "c", "d"]
        - try_files=True:
            - ["a,file.txt", "c,d"] --> ["a", "f_line1", "f_line2", "f_line3", "c", "d"]
    """
    final_list = dict()
    for entry in l:
        for s in entry.split(","):
            f = s.strip()
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
    """
    "/tmp/test" --> ["file1.txt", "file2.txt"]
    """
    directory = Path(directory).resolve()
    if directory.is_dir():
        for file in directory.iterdir():
            if file.is_file() and filter(file):
                yield file


def rm_at_exit(path):
    """
    Removes a file automatically when BBOT exits
    """
    atexit.register(_rm_at_exit, path)


def _rm_at_exit(path):
    with suppress(Exception):
        Path(path).unlink(missing_ok=True)


def read_file(filename):
    """
    "/tmp/file.txt" --> ["file_line1", "file_line2", "file_line3"]
    """
    with open(filename, errors="ignore") as f:
        for line in f:
            yield line.rstrip("\r\n")


def gen_numbers(n, padding=2):
    """
    n=5 --> ['0', '00', '01', '02', '03', '04', '1', '2', '3', '4']
    n=3, padding=3 --> ['0', '00', '000', '001', '002', '01', '02', '1', '2']
    n=5, padding=1 --> ['0', '1', '2', '3', '4']
    """
    results = set()
    for i in range(n):
        for p in range(1, padding + 1):
            results.add(str(i).zfill(p))
    return results


def make_netloc(host, port):
    """
    ("192.168.1.1", None) --> "192.168.1.1"
    ("192.168.1.1", 443) --> "192.168.1.1:443"
    ("evilcorp.com", 80) --> "evilcorp.com:80"
    ("dead::beef", 443) --> "[dead::beef]:443"
    """
    if port is None:
        return host
    if is_ip(host, version=6):
        host = f"[{host}]"
    return f"{host}:{port}"


def which(*executables):
    """
    "python" --> "/usr/bin/python"
    """
    for e in executables:
        location = shutil.which(e)
        if location:
            return location


def search_dict_by_key(key, d):
    """
    Search a dictionary by key name
    Generator, yields all values with matching keys
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
    """
    Recursively .format() string values in dictionary values
    search_format_dict({"test": "#{name} is awesome"}, name="keanu")
        --> {"test": "keanu is awesome"}
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


def filter_dict(d, *key_names, fuzzy=False, invert=False, exclude_keys=None, prev_key=None):
    """
    Recursively filter a dictionary based on key names
    filter_dict({"key1": "test", "key2": "asdf"}, "key2")
        --> {"key2": "asdf"}
    """
    if exclude_keys is None:
        exclude_keys = []
    if isinstance(exclude_keys, str):
        exclude_keys = [exclude_keys]
    ret = {}
    if isinstance(d, dict):
        for key in d:
            if key in key_names or (fuzzy and any(k in key for k in key_names)):
                if not prev_key in exclude_keys:
                    ret[key] = copy.deepcopy(d[key])
            elif isinstance(d[key], list) or isinstance(d[key], dict):
                child = filter_dict(d[key], *key_names, fuzzy=fuzzy, prev_key=key, exclude_keys=exclude_keys)
                if child:
                    ret[key] = child
    return ret


def clean_dict(d, *key_names, fuzzy=False, exclude_keys=None, prev_key=None):
    if exclude_keys is None:
        exclude_keys = []
    if isinstance(exclude_keys, str):
        exclude_keys = [exclude_keys]
    d = copy.deepcopy(d)
    if isinstance(d, dict):
        for key, val in list(d.items()):
            if key in key_names or (fuzzy and any(k in key for k in key_names)):
                if prev_key not in exclude_keys:
                    d.pop(key)
            else:
                d[key] = clean_dict(val, *key_names, fuzzy=fuzzy, prev_key=key, exclude_keys=exclude_keys)
    return d


def grouper(iterable, n):
    """
    >>> list(grouper('ABCDEFG', 3))
    [['A', 'B', 'C'], ['D', 'E', 'F'], ['G']]
    """
    iterable = iter(iterable)
    return iter(lambda: list(islice(iterable, n)), [])


def split_list(alist, wanted_parts=2):
    """
    >>> split_list([1,2,3,4,5])
    [[1, 2], [3, 4, 5]]
    """
    length = len(alist)
    return [alist[i * length // wanted_parts : (i + 1) * length // wanted_parts] for i in range(wanted_parts)]


def mkdir(path, check_writable=True, raise_error=True):
    """
    Create a directory and ensure that it's writable
    """
    path = Path(path).resolve()
    touchfile = path / f".{rand_string()}"
    try:
        path.mkdir(exist_ok=True, parents=True)
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
    make_date() --> "20220707_1325_50"
    make_date(microseconds=True) --> "20220707_1330_35167617"
    """
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
    https://evilcorp.com/api/test.php --> "php"
    /etc/test.conf --> "conf"
    /etc/passwd --> ""
    """
    s = str(s).lower().strip()
    rightmost_section = s.rsplit("/", 1)[-1]
    if "." in rightmost_section:
        extension = rightmost_section.rsplit(".", 1)[-1]
        return extension
    return ""


def backup_file(filename, max_backups=10):
    """
    rename a file as a backup

    recursively renames files up to max_backups

    backup_file("/tmp/test.txt") --> "/tmp/test.0.txt"
    backup_file("/tmp/test.0.txt") --> "/tmp/test.1.txt"
    backup_file("/tmp/test.1.txt") --> "/tmp/test.2.txt"
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
    """
    Given a directory, return the latest modified time of any contained file or directory (recursive)
    Useful for sorting directories by modified time for the purpose of cleanup, etc.

    latest_mtime("~/.bbot/scans/mushy_susan") --> 1659016928.2848816
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
    f = Path(f)
    if f.is_file():
        return f.stat().st_size
    return 0


def clean_old(d, keep=10, filter=lambda x: True, key=latest_mtime, reverse=True, raise_error=False):
    """
    Given a directory "d", measure the number of subdirectories and files (matching "filter")
    And remove (rm -r) the oldest ones past the threshold of "keep"

    clean_old_dirs("~/.bbot/scans", filter=lambda x: x.is_dir() and scan_name_regex.match(x.name))
    """
    d = Path(d)
    if not d.is_dir():
        return
    paths = [x for x in d.iterdir() if filter(x)]
    paths.sort(key=key, reverse=reverse)
    for path in paths[keep:]:
        try:
            log.debug(f"Removing {path}")
            shutil.rmtree(path)
        except Exception as e:
            msg = f"Failed to delete directory: {path}, {e}"
            if raise_error:
                raise errors.DirectoryDeletionError()
            log.warning(msg)


def extract_emails(s):
    for email in regexes.email_regex.findall(smart_decode(s)):
        yield email.lower()


def can_sudo_without_password():
    """
    Return True if the current user can sudo without a password
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
    """
    Return True if the sudo password is correct
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


def make_table(*args, **kwargs):
    """
    make_table([["row1", "row1"], ["row2", "row2"]], ["header1", "header2"]) -->

    +-----------+-----------+
    | header1   | header2   |
    +===========+===========+
    | row1      | row1      |
    +-----------+-----------+
    | row2      | row2      |
    +-----------+-----------+
    """
    # fix IndexError: list index out of range
    if args and not args[0]:
        args = ([[]],) + args[1:]
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
    return tabulate(*args, **kwargs)


def human_timedelta(d):
    """
    Format a TimeDelta object in human-readable form
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
    return ", ".join(result)


def bytes_to_human(_bytes):
    """
    Converts bytes to human-readable filesize
        bytes_to_human(1234129384) --> "1.15GB"
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
    """
    Converts human-readable filesize to bytes
        human_to_bytes("23.23gb") --> 24943022571
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


def cpu_architecture():
    """
    Returns the CPU architecture, e.g. "amd64, "armv7", "arm64", etc.
    """
    uname = platform.uname()
    arch = uname.machine.lower()
    if arch.startswith("aarch"):
        return "arm64"
    elif arch == "x86_64":
        return "amd64"
    return arch


def os_platform():
    """
    Returns the OS platform, e.g. "linux", "darwin", "windows", etc.
    """
    return platform.system().lower()


def os_platform_friendly():
    """
    Returns the OS platform in a more human-friendly format, because apple is indecisive
    """
    p = os_platform()
    if p == "darwin":
        return "macOS"
    return p


tag_filter_regex = re.compile(r"[^a-z0-9]+")


def tagify(s, maxlen=None):
    """
    Sanitize a string into a tag-friendly format

    tagify("HTTP Web Title") --> "http-web-title"
    """
    ret = str(s).lower()
    return tag_filter_regex.sub("-", ret)[:maxlen].strip("-")


def memory_status():
    """
    Return statistics on system memory consumption

    Example: to get available memory (not including swap):
        memory_status().available

    Example: to get percent memory used:
        memory_status().percent
    """
    return psutil.virtual_memory()


def swap_status():
    """
    Return statistics on swap memory consumption

    Example: to get total swap:
        swap_status().total

    Example: to get in-use swap:
        swap_status().used
    """
    return psutil.swap_memory()


def get_size(obj, max_depth=5, seen=None):
    """
    Rough recursive measurement of a python object's memory footprint
    """
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
    with suppress(Exception):
        return Path(f).is_file()
    return False


provider_map = {"amazon": "aws", "google": "gcp"}


def cloudcheck(ip):
    """
    Check whether an IP address belongs to a cloud provider

        provider, provider_type, subnet = cloudcheck("168.62.20.37")
        print(provider) # "Azure"
        print(provider_type) # "cloud"
        print(subnet) # IPv4Network('168.62.0.0/19')
    """
    provider, provider_type, subnet = _cloudcheck.check(ip)
    if provider:
        with suppress(KeyError):
            provider = provider_map[provider.lower()]
    return provider, provider_type, subnet


def is_async_function(f):
    return inspect.iscoroutinefunction(f)


async def execute_sync_or_async(callback, *args, **kwargs):
    if is_async_function(callback):
        return await callback(*args, **kwargs)
    else:
        return callback(*args, **kwargs)


def get_exception_chain(e):
    """
    Get the full chain of exceptions that led to the current one
    """
    exception_chain = []
    current_exception = e
    while current_exception is not None:
        exception_chain.append(current_exception)
        current_exception = getattr(current_exception, "__context__", None)
    return exception_chain


def get_traceback_details(e):
    tb = traceback.extract_tb(e.__traceback__)
    last_frame = tb[-1]  # Get the last frame in the traceback (the one where the exception was raised)
    filename = last_frame.filename
    lineno = last_frame.lineno
    funcname = last_frame.name
    return filename, lineno, funcname


async def cancel_tasks(tasks):
    current_task = asyncio.current_task()
    tasks = [t for t in tasks if t != current_task]
    for task in tasks:
        log.debug(f"Cancelling task: {task}")
        task.cancel()
    for task in tasks:
        try:
            await task
        except asyncio.CancelledError:
            log.trace(traceback.format_exc())


def cancel_tasks_sync(tasks):
    current_task = asyncio.current_task()
    for task in tasks:
        if task != current_task:
            log.debug(f"Cancelling task: {task}")
            task.cancel()


def weighted_shuffle(items, weights):
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
    elements = port_string.split(",")
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


def parse_list_string(list_string):
    elements = list_string.split(",")
    result = []

    for element in elements:
        if any((c in '<>:"/\\|?*') or (ord(c) < 32 and c != " ") for c in element):
            raise ValueError(f"Invalid character in string: {element}")
        result.append(element)
    return result
