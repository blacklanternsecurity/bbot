import logging

from .helpers import *
from bbot.core.errors import *
from bbot.core.helpers import extract_words, tldextract, make_host, host_in_host


log = logging.getLogger("bbot.core.event")


def make_event(*args, **kwargs):
    """
    If data is already an event, simply return it
    Handle dummy event type
    """
    dummy = kwargs.pop("dummy", False)
    data = kwargs.get("data", "")
    if not data:
        data = args[0]
    if type(data) in (Event, DummyEvent):
        return data
    else:
        if dummy:
            return DummyEvent(*args, **kwargs)
        else:
            return Event(*args, **kwargs)


class Event:

    _dummy = False

    def __init__(self, data, event_type=None, source=None, module=None):

        if event_type is None:
            event_type = get_event_type(data)
            if not self._dummy:
                log.debug(
                    f'Autodetected event type "{event_type}" based on data: "{data}"'
                )
        if event_type is None:
            raise ValidationError(
                f'Unable to autodetect event type from "{data}": please specify event_type'
            )

        if module is None:
            module = "module"
        self.module = str(module)

        self.source = None
        if type(source) == Event:
            self.source = source.id
        elif is_event_id(source):
            self.source = str(source)
        if not self.source and not self._dummy:
            raise ValidationError(f"Must specify event source")

        self.type = str(event_type).strip().upper()
        self.data = data
        for sanitizer in event_sanitizers.get(self.type, []):
            self.data = sanitizer(self.data)

        if not self.data:
            raise ValidationError(f'Invalid event data "{data}" for type "{self.type}"')

        self._id = None
        self._hash = None
        self._host = None
        self._port = None
        self._words = None
        self._data_obj = None

        if self.type == "DOMAIN" and is_subdomain(self.data):
            self.type = "SUBDOMAIN"
        elif self.type == "SUBDOMAIN" and is_domain(self.data):
            self.type = "DOMAIN"

    @property
    def host(self):
        """
        An abbreviated representation of the data that allows comparison with other events.
        For host types, this is a hostname.
        This allows comparison of an email or a URL with a domain, and vice versa
            bob@evilcorp.com --> evilcorp.com
            https://evilcorp.com --> evilcorp.com

        For IPV*_* types, this is an instantiated object representing the event's data
        E.g. for IPV4_ADDRESS, it's an ipaddress.IPv4Address() object
        """
        data = self.data
        if self._host is None:
            # IP types
            constructor = event_data_constructors.get(self.type, None)
            if constructor:
                self._host = constructor(self.data)
            # Host types
            else:
                if self.type not in scopable_types:
                    self._host = ""
                else:
                    if self.type == "EMAIL_ADDRESS":
                        data = str(self.data).split("@")[-1]
                    self._host = make_host(data)
        return self._host

    @property
    def host_stem(self):
        """
        An abbreviated representation of hostname that removes the TLD
            E.g. www.evilcorp.com --> www.evilcorp
        """
        if type(self.host) == str:
            parsed = tldextract(self.data)
            return f".".join(
                parsed.subdomain.split(".") + parsed.domain.split(".")
            ).strip(".")
        else:
            return f"{self.host}"

    @property
    def words(self):
        """
        extract words from event data
        """
        if self._words is None:
            self._words = set()
            if self.type in ("DOMAIN", "SUBDOMAIN", "EMAIL_ADDRESS", "URL"):
                self._words.update(extract_words(self.host_stem))
        return self._words

    @property
    def data_hash(self):
        if self._hash is None:
            self._hash = sha1(self.data)
        return self._hash

    @property
    def id(self):
        if self._id is None:
            self._id = make_event_id(self.data, self.type)
        return self._id

    def __contains__(self, other):
        """
        Allows events to be compared using the "in" operator:
        E.g.:
            if some_event in other_event:
                ...
        """
        other = make_event(other, dummy=True)
        # if hashes match
        if other == self:
            return True
        # if hosts match
        if self.host and other.host:
            self_host = str(self.host)
            other_host = str(other.host)
            if self.host == other.host:
                return True
            # hostnames and IPs
            return host_in_host(other.host, self.host)
        return False

    def __iter__(self):
        for i in ("type", "data", "module", "source", "id"):
            v = getattr(self, i, "")
            if v:
                yield (i, v)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        return hash(self.id)

    def __str__(self):
        return f'Event("{self.type}", "{self.data[:50]}{("..." if len(self.data) > 50 else "")}")'


class DummyEvent(Event):
    """
    Identical to Event() except that it does not require a source event
    """

    _dummy = True
