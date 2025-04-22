import ipaddress
import regex as re
from functools import cached_property
from bbot.errors import ValidationError
from bbot.core.helpers import validators
from bbot.core.helpers.misc import split_host_port, make_ip_type
from bbot.core.helpers import regexes, smart_decode, smart_encode_punycode

bbot_event_seeds = {}


"""
An "Event Seed" is a lightweight event containing only the minimum logic required to:
    - parse input to determine the event type + data
    - validate+sanitize the data
    - extract the host for scope purposes

It's useful for quickly parsing target lists without the cpu+memory overhead of creating full-fledged BBOT events

Not every type of BBOT event needs to be represented here. Only ones that are meant to be targets.
"""


class EventSeedRegistry(type):
    """
    Metaclass for EventSeed that registers all subclasses in a registry.
    """

    def __new__(mcs, name, bases, attrs):
        global bbot_event_seeds
        cls = super().__new__(mcs, name, bases, attrs)
        # Don't register the base EventSeed class
        if name != "BaseEventSeed":
            bbot_event_seeds[cls.__name__] = cls
        return cls


def EventSeed(input):
    input = smart_encode_punycode(smart_decode(input).strip())
    for _, event_class in bbot_event_seeds.items():
        if hasattr(event_class, "precheck"):
            if event_class.precheck(input):
                return event_class(input)
        else:
            for regex in event_class.regexes:
                match = regex.match(input)
                if match:
                    data = event_class.handle_match(match)
                    return event_class(data)
    raise ValidationError(f'Unable to autodetect data type from "{input}"')


class BaseEventSeed(metaclass=EventSeedRegistry):
    regexes = []
    _target_type = "TARGET"

    __slots__ = ["data", "host", "port", "input"]

    def __init__(self, data):
        self.data, self.host, self.port = self._sanitize_and_extract_host(data)
        self.input = self._override_input(data)

    @staticmethod
    def handle_match(match):
        """
        Given a regex match, returns the event data
        """
        return match.group(0)

    def _sanitize_and_extract_host(self, data):
        """
        Given the event data, returns the host

        Returns:
            tuple: (data, host, port)
        """
        return data, None, None

    def _override_input(self, input):
        return self.data

    @property
    def type(self):
        return self.__class__.__name__

    @cached_property
    def _hash(self):
        return hash(self.input)

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __str__(self):
        return f"EventSeed({self.input})"

    def __repr__(self):
        return str(self)


class IP_ADDRESS(BaseEventSeed):
    regexes = regexes.event_type_regexes["IP_ADDRESS"]

    @staticmethod
    def precheck(data):
        try:
            return ipaddress.ip_address(data)
        except ValueError:
            return False

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = ipaddress.ip_address(data)
        return str(validated), validated, None


class DNS_NAME(BaseEventSeed):
    regexes = regexes.event_type_regexes["DNS_NAME"]

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = validators.validate_host(data)
        return validated, validated, None


class IP_RANGE(BaseEventSeed):
    regexes = regexes.event_type_regexes["IP_RANGE"]

    @staticmethod
    def precheck(data):
        try:
            return ipaddress.ip_network(str(data), strict=False)
        except ValueError:
            return False

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = ipaddress.ip_network(str(data), strict=False)
        return str(validated), validated, None


class OPEN_TCP_PORT(BaseEventSeed):
    regexes = regexes.event_type_regexes["OPEN_TCP_PORT"]

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = validators.validate_open_port(data)
        host, port = split_host_port(validated)
        host = make_ip_type(host)
        return str(validated), host, port


class URL_UNVERIFIED(BaseEventSeed):
    regexes = regexes.event_type_regexes["URL"]

    _scheme_to_port = {
        "https": 443,
        "http": 80,
    }

    @staticmethod
    def _sanitize_and_extract_host(data):
        parsed_url = validators.clean_url(data, url_querystring_remove=False)
        scheme = parsed_url.scheme
        host = make_ip_type(validators.validate_host(parsed_url.hostname))
        port = parsed_url.port
        if port is None:
            port = URL_UNVERIFIED._scheme_to_port.get(scheme, None)
        return parsed_url.geturl(), host, port


class EMAIL_ADDRESS(BaseEventSeed):
    regexes = regexes.event_type_regexes["EMAIL_ADDRESS"]

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = validators.validate_email(data)
        host = validated.rsplit("@", 1)[-1]
        host, port = split_host_port(host)
        return validated, host, port


class ORG_STUB(BaseEventSeed):
    regexes = (re.compile(r"^(?:ORG|ORG_STUB):(.*)"),)

    def _override_input(self, input):
        return f"ORG_STUB:{self.data}"

    @staticmethod
    def handle_match(match):
        return match.group(1)


class USERNAME(BaseEventSeed):
    regexes = (re.compile(r"^(?:USER|USERNAME):(.*)"),)

    def _override_input(self, input):
        return f"USERNAME:{self.data}"

    @staticmethod
    def handle_match(match):
        return match.group(1)


class FILESYSTEM(BaseEventSeed):
    regexes = (re.compile(r"^(?:FILESYSTEM|FILE|FOLDER|DIR|PATH):(.*)"),)

    def _override_input(self, input):
        return f"FILESYSTEM:{self.data['path']}"

    @staticmethod
    def handle_match(match):
        return {"path": match.group(1)}


class MOBILE_APP(BaseEventSeed):
    regexes = (re.compile(r"^(?:MOBILE_APP|APK|IPA|APP):(.*)"),)

    def _override_input(self, input):
        return f"MOBILE_APP:{self.data['url']}"

    @staticmethod
    def handle_match(match):
        return {"url": match.group(1)}


class BLACKLIST_REGEX(BaseEventSeed):
    regexes = (re.compile(r"^(?:RE|REGEX):(.*)"),)
    _target_type = "BLACKLIST"

    def _override_input(self, input):
        return f"REGEX:{self.data}"

    @staticmethod
    def handle_match(match):
        return match.group(1)
