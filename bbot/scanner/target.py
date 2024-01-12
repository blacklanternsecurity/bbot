import logging
import ipaddress
from contextlib import suppress

from bbot.core.errors import *
from bbot.modules.base import BaseModule
from bbot.core.event import make_event, is_event

log = logging.getLogger("bbot.core.target")


class Target:
    """
    A class representing a target. Can contain an unlimited number of hosts, IP or IP ranges, URLs, etc.

    Attributes:
        make_in_scope (bool): Specifies whether to mark contained events as in-scope.
        scan (Scan): Reference to the Scan object that instantiated the Target.
        _events (dict): Dictionary mapping hosts to events related to the target.
        strict_scope (bool): Flag indicating whether to consider child domains in-scope.
            If set to True, only the exact hosts specified and not their children are considered part of the target.

    Examples:
        Basic usage
        >>> target = Target(scan, "evilcorp.com", "1.2.3.0/24")
        >>> len(target)
        257
        >>> list(t.events)
        [
            DNS_NAME("evilcorp.com", module=TARGET, tags={'domain', 'distance-1', 'target'}),
            IP_RANGE("1.2.3.0/24", module=TARGET, tags={'ipv4', 'distance-1', 'target'})
        ]
        >>> "www.evilcorp.com" in target
        True
        >>> "1.2.3.4" in target
        True
        >>> "4.3.2.1" in target
        False
        >>> "https://admin.evilcorp.com" in target
        True
        >>> "bob@evilcorp.com" in target
        True

        Event correlation
        >>> target.get("www.evilcorp.com")
        DNS_NAME("evilcorp.com", module=TARGET, tags={'domain', 'distance-1', 'target'})
        >>> target.get("1.2.3.4")
        IP_RANGE("1.2.3.0/24", module=TARGET, tags={'ipv4', 'distance-1', 'target'})

        Target comparison
        >>> target2 = Targets(scan, "www.evilcorp.com")
        >>> target2 == target
        False
        >>> target2 in target
        True
        >>> target in target2
        False

    Notes:
        - Targets are only precise down to the individual host. Ports and protocols are not considered in scope calculations.
        - If you specify "https://evilcorp.com:8443" as a target, all of evilcorp.com (including subdomains and other ports and protocols) will be considered part of the target
        - If you do not want to include child subdomains, use `strict_scope=True`
    """

    def __init__(self, scan, *targets, strict_scope=False, make_in_scope=False):
        """
        Initialize a Target object.

        Args:
            scan (Scan): Reference to the Scan object that instantiated the Target.
            *targets: One or more targets (e.g., domain names, IP ranges) to be included in this Target.
            strict_scope (bool, optional): Flag to control whether only the exact hosts are considered in-scope.
                                           Defaults to False.
            make_in_scope (bool, optional): Flag to control whether contained events are marked as in-scope.
                                            Defaults to False.

        Attributes:
            scan (Scan): Reference to the Scan object.
            strict_scope (bool): Flag to control in-scope conditions. If True, only exact hosts are considered.

        Notes:
            - If you are instantiating a target from within a BBOT module, use `self.helpers.make_target()` instead. (this removes the need to pass in a scan object.)
            - The strict_scope flag can be set to restrict scope calculation to only exactly-matching hosts and not their child subdomains.
            - Each target is processed and stored as an `Event` in the '_events' dictionary.
        """
        self.scan = scan
        self.strict_scope = strict_scope
        self.make_in_scope = make_in_scope

        self._dummy_module = TargetDummyModule(scan)
        self._events = dict()
        if len(targets) > 0:
            log.verbose(f"Creating events from {len(targets):,} targets")
        for t in targets:
            self.add_target(t)

        self._hash = None

    def add_target(self, t):
        """
        Add a target or merge events from another Target object into this Target.

        Args:
            t: The target to be added. It can be either a string, an event object, or another Target object.

        Attributes Modified:
            _events (dict): The dictionary is updated to include the new target's events.

        Examples:
            >>> target.add_target('example.com')

        Notes:
            - If `t` is of the same class as this Target, all its events are merged.
            - If `t` is an event, it is directly added to `_events`.
            - If `make_in_scope` is True, the scope distance of the event is set to 0.
        """
        if type(t) == self.__class__:
            for k, v in t._events.items():
                try:
                    self._events[k].update(v)
                except KeyError:
                    self._events[k] = set(t._events[k])
        else:
            if is_event(t):
                event = t
            else:
                event = self.scan.make_event(
                    t, source=self.scan.root_event, module=self._dummy_module, tags=["target"]
                )
            if self.make_in_scope:
                event.scope_distance = 0
            try:
                self._events[event.host].add(event)
            except KeyError:
                self._events[event.host] = {
                    event,
                }

    @property
    def events(self):
        """
        A generator property that yields all events in the target.

        Yields:
            Event object: One of the Event objects stored in the `_events` dictionary.

        Examples:
            >>> target = Target(scan, "example.com")
            >>> for event in target.events:
            ...     print(event)

        Notes:
            - This property is read-only.
            - Iterating over this property gives you one event at a time from the `_events` dictionary.
        """
        for _events in self._events.values():
            yield from _events

    def copy(self):
        """
        Creates and returns a copy of the Target object, including a shallow copy of the `_events` attribute.

        Returns:
            Target: A new Target object with the same `scan` and `strict_scope` attributes as the original.
                    A shallow copy of the `_events` dictionary is made.

        Examples:
            >>> original_target = Target(scan, "example.com")
            >>> copied_target = original_target.copy()
            >>> copied_target is original_target
            False
            >>> copied_target == original_target
            True
            >>> copied_target in original_target
            True
            >>> original_target in copied_target
            True

        Notes:
            - The `scan` object reference is kept intact in the copied Target object.
        """
        self_copy = self.__class__(self.scan, strict_scope=self.strict_scope)
        self_copy._events = dict(self._events)
        return self_copy

    def get(self, host):
        """
        Gets the event associated with the specified host from the target's `_events` dictionary.

        Args:
            host (Event, Target, or str): The hostname, IP, URL, or event to look for.

        Returns:
            Event or None: Returns the Event object associated with the given host if it exists, otherwise returns None.

        Examples:
            >>> target = Target(scan, "evilcorp.com", "1.2.3.0/24")
            >>> target.get("www.evilcorp.com")
            DNS_NAME("evilcorp.com", module=TARGET, tags={'domain', 'distance-1', 'target'})
            >>> target.get("1.2.3.4")
            IP_RANGE("1.2.3.0/24", module=TARGET, tags={'ipv4', 'distance-1', 'target'})

        Notes:
            - The method returns the first event that matches the given host.
            - If `strict_scope` is False, it will also consider parent domains and IP ranges.
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
        # if "other" is a Target
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
        Calculates and returns the total number of hosts within this target, not counting duplicate events.

        Returns:
            int: The total number of unique hosts present within the target's `_events`.

        Examples:
            >>> target = Target(scan, "evilcorp.com", "1.2.3.0/24")
            >>> len(target)
            257

        Notes:
            - If a host is represented as an IP network, all individual IP addresses in that network are counted.
            - For other types of hosts, each unique event is counted as one.
        """
        num_hosts = 0
        for host, _events in self._events.items():
            if type(host) in (ipaddress.IPv4Network, ipaddress.IPv6Network):
                num_hosts += host.num_addresses
            else:
                num_hosts += len(_events)
        return num_hosts


class TargetDummyModule(BaseModule):
    _type = "TARGET"
    name = "TARGET"

    def __init__(self, scan):
        self.scan = scan
