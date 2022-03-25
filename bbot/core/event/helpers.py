import logging
import ipaddress
from contextlib import suppress
from urllib.parse import urlparse

from bbot.core.helpers.regexes import event_type_regexes, event_id_regex
from bbot.core.helpers import sha1, is_domain, smart_decode

log = logging.getLogger("bbot.core.event.helpers")


def sanitize_ip_address(d):
    return f"{ipaddress.ip_address(d)}"


def sanitize_ip_network(d):
    return f"{ipaddress.ip_network(d, strict=False)}"


def sanitize_open_port(d):
    parsed = urlparse(f"d://{d}")
    return parsed.netloc


event_sanitizers = {
    "DOMAIN": [str.strip, str.lower],
    "SUBDOMAIN": [str.strip, str.lower],
    "EMAIL_ADDRESS": [str.strip, str.lower],
    "IPV4_ADDRESS": [sanitize_ip_address],
    "IPV6_ADDRESS": [sanitize_ip_address],
    "IPV4_RANGE": [sanitize_ip_network],
    "IPV6_RANGE": [sanitize_ip_network],
    "OPEN_TCP_PORT": [sanitize_open_port],
    "OPEN_UDP_PORT": [sanitize_open_port],
}

event_data_constructors = {
    "IPV4_ADDRESS": ipaddress.ip_address,
    "IPV6_ADDRESS": ipaddress.ip_address,
    "IPV4_RANGE": ipaddress.ip_network,
    "IPV6_RANGE": ipaddress.ip_network,
}


def get_event_type(data):
    """
    Attempt to divine event type from data
    """

    data = smart_decode(data)

    # IP address
    with suppress(Exception):
        ip = ipaddress.ip_address(str(data).strip())
        return f"IPV{ip.version}_ADDRESS"

    # IP network
    with suppress(Exception):
        net = ipaddress.ip_network(str(data).strip(), strict=False)
        return f"IPV{net.version}_RANGE"

    # Everything else
    for t, r in event_type_regexes.items():
        if r.match(data):
            if t == "HOSTNAME":
                if is_domain(data):
                    return "DOMAIN"
                else:
                    return "SUBDOMAIN"
            else:
                return t


def is_event_id(s):
    if event_id_regex.match(str(s)):
        return True
    return False


def make_event_id(data, event_type):
    return f"{sha1(data).hexdigest()}:{event_type}"


host_types = ("URL", "DOMAIN", "SUBDOMAIN", "EMAIL_ADDRESS")

port_types = ("OPEN_TCP_PORT", "OPEN_UDP_PORT")

host_ip_types = ("IPV4_ADDRESS", "IPV6_ADDRESS", "IPV4_RANGE", "IPV6_RANGE")

scopable_types = host_types + port_types
