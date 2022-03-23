import logging

from bbot.core.event import make_event
from bbot.core.helpers import sha1, host_in_host
from bbot.core.event.helpers import make_event_id

log = logging.getLogger("bbot.core.target")


class ScanTarget:
    def __init__(self, *targets):
        # create pseudo root event
        self.root_event = make_event(
            data="TARGET", event_type="TARGET", source=make_event_id("TARGET", "TARGET")
        )
        self._events = dict()
        for t in targets:
            if type(t) == self.__class__:
                for k, v in t._events.items():
                    self._events[k].update(v)
            else:
                event = make_event(t, source=self.root_event)
                try:
                    self._events[event.host].add(event)
                except KeyError:
                    self._events[event.host] = {
                        event,
                    }

        self._hash = None

    @property
    def events(self):
        events = set()
        for _events in self._events.values():
            events.update(_events)
        return events

    def __iter__(self):
        yield from self.events

    def __contains__(self, other):
        # if "other" is a ScanTarget
        if type(other) == self.__class__:
            return all([e in self for e in other.events])
        else:
            # otherwise, make it an event
            other = make_event(other, dummy=True)
            if other.host:
                # check if the event's host matches any of ours
                for host in self._events:
                    if host and host_in_host(other.host, host):
                        return True
                # check if the event matches any of ours
                for e in self._events.get("", []):
                    if e.host and host_in_host(other.host, e.host):
                        return True
        return False

    def __hash__(self):
        if self._hash is None:
            events = sorted(list(self.events), key=lambda e: e.id)
            event_hashes = "_".join([e.id for e in events])
            return sha1(event_hashes)

    def __bool__(self):
        return len(self.events) > 0
