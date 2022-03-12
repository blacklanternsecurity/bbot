import logging

from bbot.core.helpers import sha1
from bbot.core.event import Event, DummyEvent
from bbot.core.event.helpers import make_event_id

log = logging.getLogger('bbot.core.target')

class ScanTarget:

    def __init__(self, *targets):
        # create pseudo root event
        self.root_event = Event(data='TARGET', event_type='TARGET', source=make_event_id('TARGET', 'TARGET'))
        self.events = set()
        for t in targets:
            if type(t) == self.__class__:
                self.events.update(t.events)
            else:
                self.events.add(Event(t, source=self.root_event))

        self._hash = None

    def __contains__(self, other):
        if type(other) == self.__class__:
            return all([e in self for e in other.events])
        else:
            other = DummyEvent(other)
            return any([other in e for e in self.events])
        return False

    def __hash__(self):
        if self._hash is None:
            events = sorted(list(self.events), key=lambda e: e.id)
            event_hashes = '_'.join([e.id for e in events])
            return sha1(event_hashes)

    def __bool__(self):
        return len(self.events) > 0