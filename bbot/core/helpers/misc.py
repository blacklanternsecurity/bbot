import psutil
import random
import signal
import string
import logging
import ipaddress
import wordninja
from contextlib import suppress
import tldextract as _tldextract
from urllib.parse import urlparse
from itertools import combinations
from hashlib import sha1 as hashlib_sha1

from .regexes import word_regexes, event_type_regexes

log = logging.getLogger("bbot.core.helpers.misc")


def is_hostname(d):
    r = event_type_regexes["HOSTNAME"]
    if r.match(d):
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
    split_domain = str(d).split(".")
    if len(split_domain) == 1:
        return "."
    else:
        return ".".join(split_domain[1:])


def is_ip(d):
    try:
        ipaddress.ip_address(str(d))
        return True
    except Exception:
        pass
    return False


def is_email(d):
    if event_type_regexes["EMAIL_ADDRESS"].match(str(d)):
        return True
    return False


def make_host(s):
    s = str(s)
    if "://" in s:
        parsed = urlparse(s)
    else:
        parsed = urlparse(f"d://{s}")
    return make_ip_type(parsed.hostname)


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
        host1_net = ipaddress.ip_network(host1)
        host2_net = ipaddress.ip_network(host2)
        if host1_net.num_addresses <= host2_net.num_addresses:
            netmask = host2_net.prefixlen
            host1_net = ipaddress.ip_network(
                f"{host1_net.network_address}/{netmask}", strict=False
            )
            host2_net = ipaddress.ip_network(
                f"{host2_net.network_address}/{netmask}", strict=False
            )
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


def tldextract(data):
    return _tldextract.extract(smart_decode(data))


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
