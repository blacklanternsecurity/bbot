import os
import re
import sys
import copy
import json
import atexit
import psutil
import random
import shutil
import signal
import string
import logging
import platform
import ipaddress
import wordninja
import subprocess as sp
from pathlib import Path
from itertools import islice
from datetime import datetime
from tabulate import tabulate
from contextlib import suppress
import tldextract as _tldextract
from urllib.parse import urlparse, quote  # noqa F401
from hashlib import sha1 as hashlib_sha1

from .url import *  # noqa F401
from . import regexes
from .. import errors
from .punycode import *  # noqa F401
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


def extract_words(data, max_length=100):
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
        subwords = wordninja.split(word)
        for subword in subwords:
            words.add(subword)
        # blacklanternsecurity --> ['black', 'lantern', 'security', 'blacklantern', 'lanternsecurity']
        # for s, e in combinations(range(len(subwords) + 1), 2):
        #    if e - s <= max_slice_length:
        #        subword_slice = "".join(subwords[s:e])
        #        words.add(subword_slice)
        # blacklanternsecurity --> bls
        if len(subwords) > 1:
            words.add("".join([c[0] for c in subwords if len(c) > 0]))

    return words


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


loglevel_mapping = {
    "DEBUG": "DBUG",
    "VERBOSE": "VERB",
    "HUGEVERBOSE": "VERB",
    "INFO": "INFO",
    "HUGEINFO": "INFO",
    "SUCCESS": "SUCC",
    "HUGESUCCESS": "SUCC",
    "WARNING": "WARN",
    "HUGEWARNING": "WARN",
    "ERROR": "ERRR",
    "CRITICAL": "CRIT",
}
color_mapping = {
    "DEBUG": 242,  # grey
    "VERBOSE": 242,  # grey
    "INFO": 69,  # blue
    "HUGEINFO": 69,  # blue
    "SUCCESS": 118,  # green
    "HUGESUCCESS": 118,  # green
    "WARNING": 208,  # orange
    "HUGEWARNING": 208,  # orange
    "ERROR": 196,  # red
    "CRITICAL": 196,  # red
}
color_prefix = "\033[1;38;5;"
color_suffix = "\033[0m"


def colorize(s, level="INFO"):
    seq = color_mapping.get(level, 15)  # default white
    colored = f"{color_prefix}{seq}m{s}{color_suffix}"
    return colored


def log_to_stderr(msg, level="INFO"):
    """
    Print to stderr with BBOT logger colors
    """
    levelname = level.upper()
    if not any(x in sys.argv for x in ("-s", "--silent")):
        levelshort = f"[{loglevel_mapping.get(level, 'INFO')}]"
        levelshort = f"{colorize(levelshort, level=levelname)}"
        if levelname == "CRITICAL" or levelname.startswith("HUGE"):
            msg = colorize(msg)
        print(f"{levelshort} bbot: {msg}", file=sys.stderr)


def can_sudo_without_password():
    """
    Return True if the current user can sudo without a password
    """
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
