import logging
import ipaddress
from contextlib import suppress

from bbot.core.errors import ValidationError
from bbot.core.helpers import sha1, smart_decode, smart_decode_punycode
from bbot.core.helpers.regexes import event_type_regexes, event_id_regex, hostname_regex


log = logging.getLogger("bbot.core.event.helpers")


def get_event_type(data):
    """
    Attempt to divine event type from data
    """

    data = smart_decode_punycode(smart_decode(data).strip())

    # IP address
    with suppress(Exception):
        ipaddress.ip_address(data)
        return "IP_ADDRESS"

    # IP network
    with suppress(Exception):
        ipaddress.ip_network(data, strict=False)
        return "IP_RANGE"

    # Strict regexes
    for t, regexes in event_type_regexes.items():
        for r in regexes:
            if r.match(data):
                if t == "URL":
                    return "URL_UNVERIFIED"
                return t

    # Assume DNS_NAME for basic words
    if hostname_regex.match(data):
        return "DNS_NAME"

    raise ValidationError(f'Unable to autodetect event type from "{data}"')


def is_event_id(s):
    if event_id_regex.match(str(s)):
        return True
    return False


def make_event_id(data, event_type):
    return f"{event_type}:{sha1(data).hexdigest()}"


host_types = ("URL", "DNS_NAME", "EMAIL_ADDRESS")

port_types = ("OPEN_TCP_PORT",)

host_ip_types = ("IP_ADDRESS", "IP_ADDRESS", "IP_RANGE", "IP_RANGE")

scopable_types = host_types + port_types
