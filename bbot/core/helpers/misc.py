import os
import atexit
import psutil
import random
import signal
import string
import logging
import ipaddress
import wordninja
from pathlib import Path
from contextlib import suppress
import tldextract as _tldextract
from urllib.parse import urlparse
from itertools import combinations
from hashlib import sha1 as hashlib_sha1

from .regexes import word_regexes, event_type_regexes

log = logging.getLogger("bbot.core.helpers.misc")


def is_dns_name(d):
    if event_type_regexes["DNS_NAME"].match(d):
        return True
    return False


def is_domain(d):
    extracted = tldextract(d)
    if extracted.domain and not extracted.subdomain:
        return True
    return False


def is_subdomain(d):
    extracted = tldextract(d)
    if extracted.domain and extracted.subdomain:
        return True
    return False


def split_host_port(d):
    if not "://" in d:
        d = f"d://{d}"
    parsed = urlparse(d)
    return make_ip_type(parsed.hostname), parsed.port


def domain_parents(d):
    """
    Returns all parents of a subdomain
        test.www.evilcorp.com --> [www.evilcorp.com, evilcorp.com]
    """
    parent = str(d)
    while 1:
        parent = parent_domain(parent)
        if is_subdomain(parent):
            yield parent
            continue
        elif is_domain(parent):
            yield parent
        break


def parent_domain(d):
    if is_domain(d):
        return d
    else:
        split_domain = str(d).split(".")
        if len(split_domain) == 1:
            return "."
        else:
            return ".".join(split_domain[1:])


def is_ip(d, version=None):
    try:
        ip = ipaddress.ip_address(str(d))
        if version is None or ip.version == version:
            return True
    except Exception:
        pass
    return False


def is_email(d):
    if event_type_regexes["EMAIL_ADDRESS"].match(str(d)):
        return True
    return False


def make_ip_type(s):
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
    """

    if not host1 or not host2:
        return False

    # check if hosts are IP types
    host1_ip_type = hasattr(host1, "is_multicast")
    host2_ip_type = hasattr(host2, "is_multicast")
    # if both hosts are IP types
    if host1_ip_type and host2_ip_type:
        if not host1.version == host2.version:
            return False
        host1_net = ipaddress.ip_network(host1)
        host2_net = ipaddress.ip_network(host2)
        if host1_net.num_addresses <= host2_net.num_addresses:
            netmask = host2_net.prefixlen
            host1_net = ipaddress.ip_network(f"{host1_net.network_address}/{netmask}", strict=False)
            host2_net = ipaddress.ip_network(f"{host2_net.network_address}/{netmask}", strict=False)
            return host1_net == host2_net

    # else hostnames
    elif not (host1_ip_type or host2_ip_type):
        host2_len = len(host2.split("."))
        host1_truncated = ".".join(host1.split(".")[-host2_len:])
        return host1_truncated == host2

    return False


def sha1(data):
    if type(data) != bytes:
        data = str(data).encode("utf-8", errors="ignore")
    return hashlib_sha1(data)


def smart_decode(data):
    if type(data) == bytes:
        return data.decode("utf-8", errors="ignore")
    else:
        return str(data)


def smart_encode(data):
    if type(data) == bytes:
        return data
    return str(data).encode("utf-8", errors="ignore")


def tldextract(data):
    return _tldextract.extract(smart_decode(data))


def split_domain(hostname):
    parsed = tldextract(hostname)
    return (parsed.subdomain, parsed.registered_domain)


rand_pool = string.ascii_lowercase + string.digits


def rand_string(length=10):
    return "".join([random.choice(rand_pool) for _ in range(int(length))])


def extract_words(data, max_length=100):
    """
    Intelligently extract words from given data
    """
    words = set()
    data = smart_decode(data)

    for r in word_regexes:
        for word in set(r.findall(data)):
            # blacklanternsecurity
            if len(word) <= max_length:
                words.add(word)

    # blacklanternsecurity --> ['black', 'lantern', 'security']
    max_slice_length = 3
    for word in list(words):
        subwords = wordninja.split(word)
        # blacklanternsecurity --> ['black', 'lantern', 'security', 'blacklantern', 'lanternsecurity']
        for s, e in combinations(range(len(subwords) + 1), 2):
            if e - s <= max_slice_length:
                subword_slice = "".join(subwords[s:e])
                words.add(subword_slice)
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
        log.warning(f"No such PID: {parent_pid}")
    log.debug(f"Killing children of process ID {parent.pid}")
    children = parent.children(recursive=True)
    for child in children:
        log.debug(f"Killing child with PID {child.pid}")
        if child.name != "python":
            child.send_signal(sig)


def str_or_file(s):
    try:
        with open(s, errors="ignore") as f:
            yield from f
    except OSError:
        yield s


def chain_lists(l, try_files=False):
    """
    Chain together list, splitting entries on comma
    Optionally try to open entries as files and add their content to the list
    """
    final_list = dict()
    for entry in l:
        for s in entry.split(","):
            f = s.strip()
            if try_files:
                for line in str_or_file(f):
                    final_list[line.strip()] = None
            else:
                final_list[f] = None

    return list(final_list)


def list_files(directory, filter=lambda x: True):
    directory = Path(directory)
    if directory.is_dir():
        for file in os.listdir(directory):
            file = directory / file
            if file.is_file() and filter(file):
                yield file


def _rm_at_exit(path):
    with suppress(Exception):
        Path(path).unlink()


def rm_at_exit(path):
    atexit.register(_rm_at_exit, path)


def read_file(filename):
    with open(filename, errors="ignore") as f:
        for line in f:
            yield line.rstrip("\r\n")


def gen_numbers(n, padding=2):
    results = set()
    for i in range(n):
        for p in range(1, padding + 1):
            results.add(str(i).zfill(p))
    return results
