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
from strsimpy.qgram import QGram
import tldextract as _tldextract
from hashlib import sha1 as hashlib_sha1
from urllib.parse import urlparse, quote, unquote, urlunparse  # noqa F401

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
    extracted = tldextract(d)
    if extracted.domain and not extracted.subdomain:
        return True
    return False


def is_subdomain(d):
    """
    "www.evilcorp.co.uk" --> True
    "evilcorp.co.uk" --> False
    """
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
            if parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80
        else:
            port = int(parsed.port)
    with suppress(ValueError):
        host = parsed.hostname
    return make_ip_type(host), port


def parent_domain(d):
    """
    "www.internal.evilcorp.co.uk" --> "internal.evilcorp.co.uk"
    "www.evilcorp.co.uk" --> "evilcorp.co.uk"
    "evilcorp.co.uk" --> "evilcorp.co.uk"
    """
    if is_subdomain(d):
        return ".".join(str(d).split(".")[1:])
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


def extract_words(data, acronyms=True, wordninja=True, model=None, max_length=100):
    """
    Intelligently extract words from given data
    Returns set() of extracted words
    """
    words = set()
    data = smart_decode(data)
    for r in regexes.word_regexes:
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


def closest_match(s, choices, n=1):
    """
    Given a string and a list of choices, returns the best match

    closest_match("asdf", ["asd", "fds"]) --> ('asd', 1)
    closest_match("asdf", ["asd", "fds", "asdff"], n=3) --> [('asd', 1), ('asdff', 1), ('fds', 5)]
    """
    qgram = QGram(2)
    matches = {_: qgram.distance(_, s) for _ in choices}
    matches = sorted(matches.items(), key=lambda x: x[-1])
    if n == 1:
        return matches[0]
    return matches[:n]


def match_and_exit(s, choices, msg=None, loglevel="HUGEWARNING", exitcode=2):
    """
    Return the closest match, warn, and exit
    """
    if msg is None:
        msg = ""
    else:
        msg += " "
    closest, score = closest_match(s, choices)
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


def chain_lists(l, try_files=False, msg=None):
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

    return list(final_list)


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
    ("192.168.1.1", 443) --> "192.168.1.1:443"
    ("evilcorp.com", 80) --> "evilcorp.com:80"
    ("dead::beef", 443) --> "[dead::beef]:443"
    """
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
    Recursively .format() string values in dictionary keys
    search_format_dict({"test": "{name} is awesome"}, name="keanu")
        --> {"test": "keanu is awesome"}
    """
    if isinstance(d, dict):
        return {k: search_format_dict(v, **kwargs) for k, v in d.items()}
    elif isinstance(d, list):
        return [search_format_dict(v, **kwargs) for v in d]
    elif isinstance(d, str):
        for k, v in kwargs.items():
            d = d.replace("#{" + str(k) + "}", v)
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
    defaults = {"tablefmt": "grid", "disable_numparse": True, "maxcolwidths": 40}
    for k, v in defaults.items():
        if k not in kwargs:
            kwargs[k] = v
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


def tagify(s):
    """
    Sanitize a string into a tag-friendly format

    tagify("HTTP Web Title") --> "http-web-title"
    """
    ret = str(s).lower()
    return tag_filter_regex.sub("-", ret).strip("-")


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
    Recursively get size of object in bytes
    """
    size = 0
    if max_depth <= 0:
        return size
    new_max_depth = max_depth - 1
    try:
        size = sys.getsizeof(obj)
        if seen is None:
            seen = set()
        obj_id = id(obj)
        if obj_id in seen:
            return 0
        # Important mark as seen *before* entering recursion to gracefully handle
        # self-referential objects
        seen.add(obj_id)
        if hasattr(obj, "__dict__"):
            for _cls in obj.__class__.__mro__:
                if "__dict__" in _cls.__dict__:
                    d = _cls.__dict__["__dict__"]
                    if inspect.isgetsetdescriptor(d) or inspect.ismemberdescriptor(d):
                        size += get_size(obj.__dict__, max_depth=new_max_depth, seen=seen)
                    break
        if isinstance(obj, dict):
            size += sum((get_size(v, max_depth=new_max_depth, seen=seen) for v in obj.values()))
            size += sum((get_size(k, max_depth=new_max_depth, seen=seen) for k in obj.keys()))
        # elif hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes, bytearray)):
        #     size += sum((get_size(i, seen) for i in obj))
        if hasattr(obj, "__slots__"):  # can have __slots__ with __dict__
            size += sum(
                get_size(getattr(obj, s), max_depth=new_max_depth, seen=seen) for s in obj.__slots__ if hasattr(obj, s)
            )
    except Exception as e:
        log.debug(f"Error getting size of {obj}: {e}")
        log.trace(traceback.format_exc())

    return size
