import logging
import ipaddress
from contextlib import suppress

from bbot.core.errors import *
from bbot.core.event import make_event
from bbot.modules.base import BaseModule

log = logging.getLogger("bbot.core.target")


class ScanTarget:
    def __init__(self, scan, *targets, strict_scope=False):
        self.scan = scan
        self.dummy_module = ScanTargetDummyModule(scan)
        self._events = dict()
        if len(targets) > 0:
            log.verbose(f"Creating events from {len(targets):,} targets")
        for t in targets:
            self.add_target(t)

        self.strict_scope = strict_scope
        self._hash = None

    def add_target(self, t):
        if type(t) == self.__class__:
            for k, v in t._events.items():
                self._events[k].update(v)
        else:
            event = self.scan.make_event(t, source=self.scan.root_event, module=self.dummy_module, tags=["target"])
            event.make_in_scope()
            try:
                self._events[event.host].add(event)
            except KeyError:
                self._events[event.host] = {
                    event,
                }

    @property
    def events(self):
        for _events in self._events.values():
            yield from _events

    def copy(self):
        self_copy = self.__class__(self.scan, strict_scope=self.strict_scope)
        self_copy._events = dict(self._events)
        return self_copy

    def get(self, host):
        """
        Get the matching target for a specified host. If not found, return None
        """
        try:
            other = make_event(host, dummy=True)
        except ValidationError:
            return
        if other.host:
            with suppress(KeyError, StopIteration):
                return next(iter(self._events[other.host]))
            if self.scan.helpers.is_ip_type(other.host):
                for n in self.scan.helpers.ip_network_parents(other.host, include_self=True):
                    with suppress(KeyError, StopIteration):
                        return next(iter(self._events[n]))
            elif not self.strict_scope:
                for h in self.scan.helpers.domain_parents(other.host):
                    with suppress(KeyError, StopIteration):
                        return next(iter(self._events[h]))

    def _contains(self, other):
        if self.get(other) is not None:
            return True
        return False

    def __str__(self):
        return ",".join([str(e.data) for e in self.events][:5])

    def __iter__(self):
        yield from self.events

    def __contains__(self, other):
        # if "other" is a ScanTarget
        if type(other) == self.__class__:
            contained_in_self = [self._contains(e) for e in other.events]
            return all(contained_in_self)
        else:
            return self._contains(other)

    def __bool__(self):
        return bool(self._events)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        if self._hash is None:
            events = tuple(sorted(list(self.events), key=lambda e: hash(e)))
            self._hash = hash(events)
        return self._hash

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


class ScanTargetDummyModule(BaseModule):
    _type = "TARGET"
    name = "TARGET"

    def __init__(self, scan):
        self.scan = scan
