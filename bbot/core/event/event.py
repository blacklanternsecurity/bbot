import logging
import ipaddress

from .helpers import *
from bbot.core.errors import *
from bbot.core.helpers import extract_words, tldextract, smart_decode


log = logging.getLogger('bbot.core.event')


class Event:

    _dummy = False

    def __call__(cls, data, event_type=None, source=None):
        '''
        If data is already an event, simply return it
        '''
        if type(data) == Event:
            return data
        else:
            return cls.__new__(cls, data, event_type, source)

    def __init__(self, data, event_type=None, source=None):

        if event_type is None:
            event_type = get_event_type(data)
            if not self._dummy:
                log.debug(f'Autodetected event type "{event_type}" based on data: "{data}"')
        if event_type is None:
            raise ValidationError(f'Unable to autodetect event type from "{data}": please specify event_type')

        self.source = None
        if type(source) == Event:
            self.source = source.id
        elif is_event_id(source):
            self.source = str(source)
        if not self.source and not self._dummy:
            raise ValidationError(f'Must specify event source')
            
        self.type = str(event_type).strip().upper()
        self.data = data
        for sanitizer in event_sanitizers.get(self.type, []):
            self.data = sanitizer(self.data)

        if not self.data:
            raise ValidationError(f'Invalid event data "{data}" for type "{self.type}"')

        self._id = None
        self._hash = None
        self._words = None
        self._data_obj = None

        if self.type == 'DOMAIN' and is_subdomain(self.data):
            self.type = 'SUBDOMAIN'
        elif self.type == 'SUBDOMAIN' and is_domain(self.data):
            self.type = 'DOMAIN'

    @property
    def data_obj(self):
        '''
        For some event types, this is an instantiated object representing the event's data
        E.g. for IPV4_ADDRESS, it's an ipaddress.IPv4Address() object
        '''
        if self._data_obj is None:
            constructor = event_data_constructors.get(self.type, None)
            if constructor:
                self._data_obj = constructor(self.data)
            else:
                self._data_obj = self.data
        return self._data_obj

    @property
    def host(self):
        '''
        An abbreviated representation of the data that allows comparison with other events.
            bob@evilcorp.com --> evilcorp.com
            https://evilcorp.com --> evilcorp.com
        '''
        return tldextract(self.data).fqdn

    @property
    def host_stem(self):
        '''
        An abbreviated representation of hostname that removes the TLD
            E.g. www.evilcorp.com --> www.evilcorp
        '''
        # special case for email
        parsed = tldextract(self.data)
        return f'.'.join(parsed.subdomain.split('.') + parsed.domain.split('.'))

    @property
    def words(self):
        '''
        extract words from event data
        '''
        if self._words is None:
            self._words = set()
            if self.type in ['DOMAIN', 'SUBDOMAIN', 'EMAIL_ADDRESS', 'URL']:
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
        '''
        Allows events to be compared using the "in" operator:
        E.g.:
            if some_event in other_event:
                ...
        '''
        other = DummyEvent(other)
        return event_in_other(other, self)

    def __iter__(self):
        for i in ('type', 'data', 'source', 'id'):
            v = getattr(self, i, '')
            if v:
                yield (i, v)

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        return f'Event("{self.type}", "{self.data[:50]}{("..." if len(self.data) > 50 else "")}")'

    def __str__(self):
        return smart_decode(self.data)


class DummyEvent(Event):
    '''
    Identical to Event() except that it does not require a source event
    '''
    _dummy = True