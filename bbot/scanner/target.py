import logging
import ipaddress

from bbot.core.errors import *
from bbot.core.event import make_event

log = logging.getLogger("bbot.core.target")


class ScanTarget:
    def __init__(self, scan, *targets):
        self.scan = scan
        # create pseudo root event
        self._events = dict()
        self._events_set = None
        if len(targets) > 0:
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
        for _events in self._events.values():
            yield from _events

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
        if other in self.events:
            return True
        if other.host:
            if other.host in self._events:
                return True
            if self.scan.helpers.is_ip_type(other.host):
                for n in self.scan.helpers.ip_network_parents(other.host, include_self=True):
                    if n in self._events:
                        return True
            else:
                for h in self.scan.helpers.domain_parents(other.host):
                    if h in self._events:
                        return True
        return False

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        if self._hash is None:
            events = tuple(sorted(list(self.events), key=lambda e: hash(e)))
            return hash(events)

    def __len__(self):
        """
        Returns the total number of HOSTS (not events) in the target
        """
        num_hosts = 0
        for host, _events in self._events.items():
            if type(host) in (ipaddress.IPv4Network, ipaddress.IPv6Network):
                num_hosts += host.num_addresses
            else:
                num_hosts += len(_events)
        return num_hosts

    def __bool__(self):
        return len(list(self._events)) > 0
