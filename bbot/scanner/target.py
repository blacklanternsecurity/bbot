import logging

from bbot.core.errors import *
from bbot.core.event import make_event
from bbot.core.helpers import host_in_host

log = logging.getLogger("bbot.core.target")


class ScanTarget:
    def __init__(self, scan, *targets):
        self.scan = scan
        # create pseudo root event
        self._events = dict()
        log.info(f"Creating events from {len(targets):,} targets")
        for t in targets:
            if type(t) == self.__class__:
                for k, v in t._events.items():
                    self._events[k].update(v)
            else:
                event = self.scan.make_event(t, source=self.scan.root_event, tags=["target", "in_scope"])
                try:
                    self._events[event.host].add(event)
                except KeyError:
                    self._events[event.host] = {
                        event,
                    }

        self._hash = None

    def in_scope(self, e):
        e = make_event(e, dummy=True)
        return "in_scope" in e.tags or e in self

    @property
    def events(self):
        events = set()
        for _events in self._events.values():
            events.update(_events)
        return events

    def __str__(self):
        return ",".join([str(e.data) for e in self.events][:5])

    def __iter__(self):
        yield from self.events

    def __contains__(self, other):
        # if "other" is a ScanTarget
        if type(other) == self.__class__:
            contained_in_self = [self._contains(e, ignore_tags=True) for e in other.events]
            return all(contained_in_self)
        else:
            return self._contains(other)

    def _contains(self, other, ignore_tags=False):
        try:
            other = make_event(other, dummy=True)
        except ValidationError:
            return False
        if not ignore_tags and any([t in other.tags for t in ("in_scope", "target")]):
            return True
        if other.host:
            if other in self.events:
                return True
            if not self.scan.helpers.is_ip(other.host):
                for h in self.scan.helpers.domain_parents(other.host):
                    if h in self._events:
                        return True
            # check if the event's host matches any of ours
            # todo: don't do this
            for host in self._events:
                if host and host_in_host(other.host, host):
                    return True
            # check if the event matches any of ours
            # for e in self._events.get("", []):
            #    if e.host and host_in_host(other.host, e.host):
            #        return True
        return False

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        if self._hash is None:
            events = tuple(sorted(list(self.events), key=lambda e: hash(e)))
            return hash(events)

    def __bool__(self):
        return len(self.events) > 0
