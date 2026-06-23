import regex as re
from functools import cached_property
from bbot.errors import ValidationError
from bbot.core.helpers import validators
from bbot.core.helpers.misc import split_host_port, make_ip_type, cached_ip_address, cached_ip_network
from bbot.core.helpers import regexes, smart_decode, smart_encode_punycode

bbot_event_seeds = {}


# Pre-compute sorted event classes for performance
# This is computed once when the module is loaded instead of on every EventSeed() call
def _get_sorted_event_classes():
    """
    Sort event classes by priority (higher priority first).
    This ensures specific patterns like ASN:12345 are checked before broad patterns like hostname:port.
    """
    return sorted(bbot_event_seeds.items(), key=lambda x: getattr(x[1], "priority", 5), reverse=True)


# This will be populated after all event seed classes are registered
_sorted_event_classes = None


"""
An "Event Seed" is a lightweight event containing only the minimum logic required to:
    - parse input to determine the event type + data
    - validate+sanitize the data
    - extract the host for scope purposes

It's useful for quickly parsing target lists without the cpu+memory overhead of creating full-fledged BBOT events

Not every type of BBOT event needs to be represented here. Only ones that are meant to be targets.

PRIORITY SYSTEM:
Event seeds support a priority system to control the order in which regex patterns are checked.
This prevents conflicts where one event type's regex might incorrectly match another type's input.

Priority values:
- Higher numbers = checked first
- Default priority = 5
- Range: 1-10

To set priority on an event seed class:
    class MyEventSeed(BaseEventSeed):
        priority = 8  # Higher than default, will be checked before most others
"""


class EventSeedRegistry(type):
    """
    Metaclass for EventSeed that registers all subclasses in a registry.
    """

    def __new__(mcs, name, bases, attrs):
        global bbot_event_seeds, _sorted_event_classes
        cls = super().__new__(mcs, name, bases, attrs)
        # Don't register the base EventSeed class
        if name != "BaseEventSeed":
            bbot_event_seeds[cls.__name__] = cls
            # Recompute sorted classes whenever a new event seed is registered
            _sorted_event_classes = _get_sorted_event_classes()
        return cls


def EventSeed(input):
    input = smart_encode_punycode(smart_decode(input).strip())

    # Use pre-computed sorted event classes for better performance
    global _sorted_event_classes
    if _sorted_event_classes is None:
        _sorted_event_classes = _get_sorted_event_classes()

    for _, event_class in _sorted_event_classes:
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
    priority = 5  # Default priority for event seed matching (1-10, higher = checked first)

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

    async def _generate_children(self, helpers):
        return []

    def _override_input(self, input):
        return self.data

    @property
    def type(self):
        return self.__class__.__name__

    @property
    def url(self):
        if self.type == "URL_UNVERIFIED":
            return self.data
        return ""

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
            return cached_ip_address(data)
        except ValueError:
            return False

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = cached_ip_address(data)
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
            return cached_ip_network(str(data))
        except ValueError:
            return False

    @staticmethod
    def _sanitize_and_extract_host(data):
        validated = cached_ip_network(str(data))
        return str(validated), validated, None


class OPEN_TCP_PORT(BaseEventSeed):
    regexes = regexes.event_type_regexes["OPEN_TCP_PORT"]
    priority = 1  # Low priority: broad hostname:port pattern should be checked after specific patterns

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


class ASN(BaseEventSeed):
    regexes = (re.compile(r"^(?:ASN|AS):?(\d+)$", re.I),)  # adjust regex to match ASN:17178 AS17178
    priority = 10  # High priority

    def _override_input(self, input):
        return f"ASN:{self.data}"

    # ASNs are essentially a superset of IP_RANGES. This resolves the ASN to its
    # subnets via the shared ASN helper and emits each CIDR as a child seed,
    # which is later resolved to an IP_RANGE seed and added to the target.
    async def _generate_children(self, helpers):
        asn_data = await helpers.asn.asn_to_subnets(self.data)
        subnets = asn_data.get("subnets") or []
        if isinstance(subnets, str):
            subnets = [subnets]
        return list(subnets)

    @staticmethod
    def handle_match(match):
        return match.group(1)
