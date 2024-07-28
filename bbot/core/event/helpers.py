import logging
import ipaddress
from contextlib import suppress

from bbot.errors import ValidationError
from bbot.core.helpers.regexes import event_type_regexes
from bbot.core.helpers import smart_decode, smart_encode_punycode


log = logging.getLogger("bbot.core.event.helpers")


def get_event_type(data):
    """
    Determines the type of event based on the given data.

    Args:
        data (str): The data to be used for determining the event type.

    Returns:
        str: The type of event such as "IP_ADDRESS", "IP_RANGE", or "URL_UNVERIFIED".

    Raises:
        ValidationError: If the event type could not be determined.

    Notes:
        - Utilizes `smart_decode_punycode` and `smart_decode` to preprocess the data.
        - Makes use of `ipaddress` standard library to check for IP and network types.
        - Checks against a set of predefined regular expressions stored in `event_type_regexes`.
    """

    # IP address
    with suppress(Exception):
        ipaddress.ip_address(data)
        return "IP_ADDRESS", data

    # IP network
    with suppress(Exception):
        ipaddress.ip_network(data, strict=False)
        return "IP_RANGE", data

    data = smart_encode_punycode(smart_decode(data).strip())

    # Strict regexes
    for t, regexes in event_type_regexes.items():
        for r in regexes:
            if r.match(data):
                if t == "URL":
                    return "URL_UNVERIFIED", data
                return t, data

    raise ValidationError(f'Unable to autodetect event type from "{data}"')
