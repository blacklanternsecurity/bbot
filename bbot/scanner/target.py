import re
import copy
import logging
import ipaddress
from contextlib import suppress
from radixtarget import RadixTarget

from bbot.errors import *
from bbot.modules.base import BaseModule
from bbot.core.helpers.misc import make_ip_type
from bbot.core.event import make_event, is_event

log = logging.getLogger("bbot.core.target")


class BBOTTarget:
    """
    A convenient abstraction of a scan target that includes whitelisting and blacklisting

    Provides high-level functions like in_scope(), which includes both whitelist and blacklist checks.
    """

    def __init__(self, targets, whitelist=None, blacklist=None, strict_scope=False):
        self.strict_scope = strict_scope
        self.seeds = Target(*targets, strict_scope=self.strict_scope)
        if whitelist is None:
            self.whitelist = None
        else:
            self.whitelist = Target(*whitelist, strict_scope=self.strict_scope)
        if blacklist is None:
            blacklist = []
        self.blacklist = Target(*blacklist)

    def __iter__(self):
        return iter(self.seeds)

    def __len__(self):
        return len(self.seeds)

    def __contains__(self, other):
        return other in self.seeds

    @property
    def events(self):
        return self.seeds.events

    def in_scope(self, host):
        """
        Check whether a hostname, url, IP, etc. is in scope.
        Accepts either events or string data.

        Checks whitelist and blacklist.
        If `host` is an event and its scope distance is zero, it will automatically be considered in-scope.

        Examples:
            Check if a URL is in scope:
            >>> preset.in_scope("http://www.evilcorp.com")
            True
        """
        try:
            e = make_event(host, dummy=True)
        except ValidationError:
            return False
        in_scope = e.scope_distance == 0 or self.whitelisted(e)
        return in_scope and not self.blacklisted(e)

    def blacklisted(self, host):
        """
        Check whether a hostname, url, IP, etc. is blacklisted.

        Note that `host` can be a hostname, IP address, CIDR, email address, or any BBOT `Event` with the `host` attribute.

        Args:
            host (str or IPAddress or Event): The host to check against the blacklist

        Examples:
            Check if a URL's host is blacklisted:
            >>> preset.blacklisted("http://www.evilcorp.com")
            True
        """
        e = make_event(host, dummy=True)
        return e in self.blacklist

    def whitelisted(self, host):
        """
        Check whether a hostname, url, IP, etc. is whitelisted.

        Note that `host` can be a hostname, IP address, CIDR, email address, or any BBOT `Event` with the `host` attribute.

        Args:
            host (str or IPAddress or Event): The host to check against the whitelist

        Examples:
            Check if a URL's host is whitelisted:
            >>> preset.whitelisted("http://www.evilcorp.com")
            True
        """
        e = make_event(host, dummy=True)
        return e in self.whitelist

    @property
    def radix_only(self):
        """
        A slimmer, serializable version of the target designed for simple scope checks
        """
        return self.__class__(
            targets=[e.host for e in self.seeds if e.host],
            whitelist=[e.host for e in self.whitelist if e.host],
            blacklist=[e.host for e in self.blacklist if e.host],
            strict_scope=self.strict_scope,
        )


class Target:
    """
    A class representing a target. Can contain an unlimited number of hosts, IP or IP ranges, URLs, etc.

    Attributes:
        strict_scope (bool): Flag indicating whether to consider child domains in-scope.
            If set to True, only the exact hosts specified and not their children are considered part of the target.

        _radix (RadixTree): Radix tree for quick IP/DNS lookups.
        _events (set): Flat set of contained events.

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

    def __init__(self, *targets, strict_scope=False):
        """
        Initialize a Target object.

        Args:
            scan (Scan): Reference to the Scan object that instantiated the Target.
            *targets: One or more targets (e.g., domain names, IP ranges) to be included in this Target.

        Attributes:
            scan (Scan): Reference to the Scan object.
            strict_scope (bool): Flag to control in-scope conditions. If True, only exact hosts are considered.

        Notes:
            - If you are instantiating a target from within a BBOT module, use `self.helpers.make_target()` instead. (this removes the need to pass in a scan object.)
            - The strict_scope flag can be set to restrict scope calculation to only exactly-matching hosts and not their child subdomains.
            - Each target is processed and stored as an `Event` in the '_events' dictionary.
        """
        self.strict_scope = strict_scope
        self.special_event_types = {
            "ORG_STUB": re.compile(r"^ORG:(.*)", re.IGNORECASE),
            "ASN": re.compile(r"^ASN:(.*)", re.IGNORECASE),
        }
        self._events = set()
        self._radix = RadixTarget()

        if len(targets) > 0:
            log.verbose(f"Creating events from {len(targets):,} targets")
        for t in targets:
            self.add(t)

        self._hash = None

    def add(self, t, event_type=None):
        """
        Add a target or merge events from another Target object into this Target.

        Args:
            t: The target to be added. It can be either a string, an event object, or another Target object.

        Attributes Modified:
            _events (dict): The dictionary is updated to include the new target's events.

        Examples:
            >>> target.add('example.com')

        Notes:
            - If `t` is of the same class as this Target, all its events are merged.
            - If `t` is an event, it is directly added to `_events`.
        """
        if not isinstance(t, (list, tuple, set)):
            t = [t]
        for single_target in t:
            if isinstance(single_target, self.__class__):
                for event in single_target.events:
                    self._add_event(event)
            else:
                if is_event(single_target):
                    event = single_target
                else:
                    single_target = str(single_target)
                    for eventtype, regex in self.special_event_types.items():
                        match = regex.match(single_target)
                        if match:
                            single_target = match.groups()[0]
                            event_type = eventtype
                            break
                    try:
                        event = make_event(
                            single_target,
                            event_type=event_type,
                            dummy=True,
                            tags=["target"],
                        )
                    except ValidationError as e:
                        # allow commented lines
                        if not str(t).startswith("#"):
                            raise ValidationError(f'Could not add target "{t}": {e}')
                self._add_event(event)

    @property
    def events(self):
        """
        Returns all events in the target.

        Yields:
            Event object: One of the Event objects stored in the `_events` dictionary.

        Examples:
            >>> target = Target(scan, "example.com")
            >>> for event in target.events:
            ...     print(event)

        Notes:
            - This property is read-only.
        """
        return self._events

    def copy(self):
        """
        Creates and returns a copy of the Target object, including a shallow copy of the `_events` and `_radix` attributes.

        Returns:
            Target: A new Target object with the sameattributes as the original.
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
        self_copy = self.__class__()
        self_copy._events = set(self._events)
        self_copy._radix = copy.copy(self._radix)
        return self_copy

    def get(self, host):
        """
        Gets the event associated with the specified host from the target's radix tree.

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
            event = make_event(host, dummy=True)
        except ValidationError:
            return
        if event.host:
            return self.get_host(event.host)

    def get_host(self, host):
        """
        A more efficient version of .get() that only accepts hostnames and IP addresses
        """
        host = make_ip_type(host)
        with suppress(KeyError, StopIteration):
            result = self._radix.search(host)
            if result is not None:
                for event in result:
                    # if the result is a dns name and strict scope is enabled
                    if isinstance(event.host, str) and self.strict_scope:
                        # if the result doesn't exactly equal the host, abort
                        if event.host != host:
                            return
                    return event

    def _add_event(self, event):
        radix_data = self._radix.search(event.host)
        if radix_data is None:
            radix_data = {event}
            self._radix.insert(event.host, radix_data)
        else:
            radix_data.add(event)
        self._events.add(event)

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
        for event in self._events:
            if isinstance(event.host, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                num_hosts += event.host.num_addresses
            else:
                num_hosts += 1
        return num_hosts


class TargetDummyModule(BaseModule):
    _type = "TARGET"
    name = "TARGET"

    def __init__(self, scan):
        self.scan = scan
