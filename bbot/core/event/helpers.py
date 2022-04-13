import logging
import ipaddress
from contextlib import suppress

from bbot.core.helpers import sha1, smart_decode
from bbot.core.helpers.regexes import event_type_regexes, event_id_regex


log = logging.getLogger("bbot.core.event.helpers")


def get_event_type(data):
    """
    Attempt to divine event type from data
    """

    data = smart_decode(data)

    # IP address
    with suppress(Exception):
        ipaddress.ip_address(str(data).strip())
        return "IP_ADDRESS"

    # IP network
    with suppress(Exception):
        ipaddress.ip_network(str(data).strip(), strict=False)
        return "IP_RANGE"

    # Everything else
    for t, r in event_type_regexes.items():
        if r.match(data):
            return t


def is_event_id(s):
    if event_id_regex.match(str(s)):
        return True
    return False


def make_event_id(data, event_type):
    return f"{sha1(data).hexdigest()}:{event_type}"


host_types = ("URL", "DNS_NAME", "EMAIL_ADDRESS")

port_types = ("OPEN_TCP_PORT",)

host_ip_types = ("IP_ADDRESS", "IP_ADDRESS", "IP_RANGE", "IP_RANGE")

scopable_types = host_types + port_types
