import re
import copy
import logging
import ipaddress
import traceback
from hashlib import sha1
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

    def __init__(self, *targets, whitelist=None, blacklist=None, strict_scope=False, scan=None):
        self.strict_scope = strict_scope
        self.scan = scan
        if len(targets) > 0:
            log.verbose(f"Creating events from {len(targets):,} targets")
        self.seeds = Target(*targets, strict_scope=self.strict_scope, scan=scan)
        if whitelist is None:
            whitelist = set([e.host for e in self.seeds if e.host])
        else:
            log.verbose(f"Creating events from {len(whitelist):,} whitelist entries")
        self.whitelist = Target(*whitelist, strict_scope=self.strict_scope, scan=scan, acl_mode=True)
        if blacklist is None:
            blacklist = []
        if blacklist:
            log.verbose(f"Creating events from {len(blacklist):,} blacklist entries")
        self.blacklist = Target(*blacklist, scan=scan, acl_mode=True)
        self._hash = None

    def add(self, *args, **kwargs):
        self.seeds.add(*args, **kwargs)
        self._hash = None

    def get(self, host):
        return self.seeds.get(host)

    def get_host(self, host):
        return self.seeds.get(host)

    def __iter__(self):
        return iter(self.seeds)

    def __len__(self):
        return len(self.seeds)

    def __contains__(self, other):
        if isinstance(other, self.__class__):
            other = other.seeds
        return other in self.seeds

    def __bool__(self):
        return bool(self.seeds)

    def __eq__(self, other):
        return self.hash == other.hash

    @property
    def hash(self):
        """
        A sha1 hash representing a BBOT target and all three of its components (seeds, whitelist, blacklist)

        This can be used to compare targets.

        Examples:
            >>> target1 = BBOTTarget("evilcorp.com", blacklist=["prod.evilcorp.com"], whitelist=["test.evilcorp.com"])
            >>> target2 = BBOTTarget("evilcorp.com", blacklist=["prod.evilcorp.com"], whitelist=["test.evilcorp.com"])
            >>> target3 = BBOTTarget("evilcorp.com", blacklist=["prod.evilcorp.com"])
            >>> target1 == target2
            True
            >>> target1 == target3
            False
        """
        if self._hash is None:
            # Create a new SHA-1 hash object
            sha1_hash = sha1()
            # Update the SHA-1 object with the hash values of each object
            for target_hash in [t.hash for t in (self.seeds, self.whitelist, self.blacklist)]:
                # Convert the hash value to bytes and update the SHA-1 object
                sha1_hash.update(target_hash)
            self._hash = sha1_hash.digest()
        return self._hash

    @property
    def scope_hash(self):
        """
        A sha1 hash representing only the whitelist and blacklist

        This is used to record the scope of a scan.
        """
        # Create a new SHA-1 hash object
        sha1_hash = sha1()
        # Update the SHA-1 object with the hash values of each object
        for target_hash in [t.hash for t in (self.whitelist, self.blacklist)]:
            # Convert the hash value to bytes and update the SHA-1 object
            sha1_hash.update(target_hash)
        return sha1_hash.digest()

    @property
    def json(self):
        return {
            "seeds": sorted([e.data for e in self.seeds]),
            "whitelist": sorted([e.data for e in self.whitelist]),
            "blacklist": sorted([e.data for e in self.blacklist]),
            "strict_scope": self.strict_scope,
            "hash": self.hash.hex(),
            "seed_hash": self.seeds.hash.hex(),
            "whitelist_hash": self.whitelist.hash.hex(),
            "blacklist_hash": self.blacklist.hash.hex(),
            "scope_hash": self.scope_hash.hex(),
        }

    def copy(self):
        self_copy = copy.copy(self)
        self_copy.seeds = self.seeds.copy()
        self_copy.whitelist = self.whitelist.copy()
        self_copy.blacklist = self.blacklist.copy()
        return self_copy

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
        whitelist = self.whitelist
        if whitelist is None:
            whitelist = self.seeds
        return e in whitelist

    @property
    def radix_only(self):
        """
        A slimmer, serializable version of the target designed for simple scope checks

        This version doesn't have the events, only their hosts.
        """
        return self.__class__(
            *[e.host for e in self.seeds if e.host],
            whitelist=None if self.whitelist is None else [e for e in self.whitelist],
            blacklist=[e for e in self.blacklist],
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

    def __init__(self, *targets, strict_scope=False, scan=None, acl_mode=False):
        """
        Initialize a Target object.

        Args:
            *targets: One or more targets (e.g., domain names, IP ranges) to be included in this Target.
            strict_scope (bool): Whether to consider subdomains of target domains in-scope
            scan (Scan): Reference to the Scan object that instantiated the Target.
            acl_mode (bool): Stricter deduplication for more efficient checks

        Notes:
            - If you are instantiating a target from within a BBOT module, use `self.helpers.make_target()` instead. (this removes the need to pass in a scan object.)
            - The strict_scope flag can be set to restrict scope calculation to only exactly-matching hosts and not their child subdomains.
            - Each target is processed and stored as an `Event` in the '_events' dictionary.
        """
        self.scan = scan
        self.strict_scope = strict_scope
        self.acl_mode = acl_mode
        self.special_event_types = {
            "ORG_STUB": re.compile(r"^(?:ORG|ORG_STUB):(.*)", re.IGNORECASE),
            "USERNAME": re.compile(r"^(?:USER|USERNAME):(.*)", re.IGNORECASE),
        }
        self._events = set()
        self._radix = RadixTarget()

        for target_event in self._make_events(targets):
            self._add_event(target_event)

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
                    try:
                        event = make_event(
                            single_target, event_type=event_type, dummy=True, tags=["target"], scan=self.scan
                        )
                    except ValidationError as e:
                        # allow commented lines
                        if not str(t).startswith("#"):
                            log.trace(traceback.format_exc())
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

    @property
    def hosts(self):
        return [e.host for e in self.events]

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

    def get(self, host, single=True):
        """
        Gets the event associated with the specified host from the target's radix tree.

        Args:
            host (Event, Target, or str): The hostname, IP, URL, or event to look for.
            single (bool): Whether to return a single event. If False, return all events matching the host

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
            return self.get_host(event.host, single=single)

    def get_host(self, host, single=True):
        """
        A more efficient version of .get() that only accepts hostnames and IP addresses
        """
        host = make_ip_type(host)
        with suppress(KeyError, StopIteration):
            result = self._radix.search(host)
            if result is not None:
                ret = set()
                for event in result:
                    # if the result is a dns name and strict scope is enabled
                    if isinstance(event.host, str) and self.strict_scope:
                        # if the result doesn't exactly equal the host, abort
                        if event.host != host:
                            return
                    if single:
                        return event
                    else:
                        ret.add(event)
                if ret and not single:
                    return ret

    def _sort_events(self, events):
        return sorted(events, key=lambda x: x._host_size)

    def _make_events(self, targets):
        events = []
        for target in targets:
            event_type = None
            for eventtype, regex in self.special_event_types.items():
                if isinstance(target, str):
                    match = regex.match(target)
                    if match:
                        target = match.groups()[0]
                        event_type = eventtype
                        break
            events.append(make_event(target, event_type=event_type, dummy=True, scan=self.scan))
        return self._sort_events(events)

    def _add_event(self, event):
        skip = False
        if event.host:
            radix_data = self._radix.search(event.host)
            if self.acl_mode:
                # skip if the hostname/IP/subnet (or its parent) has already been added
                if radix_data is not None and not self.strict_scope:
                    skip = True
                else:
                    event_type = "IP_RANGE" if event.type == "IP_RANGE" else "DNS_NAME"
                    event = make_event(event.host, event_type=event_type, dummy=True, scan=self.scan)
            if not skip:
                # if strict scope is enabled and it's not an exact host match, we add a whole new entry
                if radix_data is None or (self.strict_scope and event.host not in radix_data):
                    radix_data = {event}
                    self._radix.insert(event.host, radix_data)
                # otherwise, we add the event to the set
                else:
                    radix_data.add(event)
                # clear hash
                self._hash = None
        elif self.acl_mode and not self.strict_scope:
            # skip if we're in ACL mode and there's no host
            skip = True
        if not skip:
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
        if isinstance(other, self.__class__):
            contained_in_self = [self._contains(e) for e in other.events]
            return all(contained_in_self)
        else:
            return self._contains(other)

    def __bool__(self):
        return bool(self._events)

    def __eq__(self, other):
        return self.hash == other.hash

    @property
    def hash(self):
        if self._hash is None:
            # Create a new SHA-1 hash object
            sha1_hash = sha1()
            # Update the SHA-1 object with the hash values of each object
            for event_type, event_hash in sorted([(e.type.encode(), e.data_hash) for e in self.events]):
                sha1_hash.update(event_type)
                sha1_hash.update(event_hash)
            if self.strict_scope:
                sha1_hash.update(b"\x00")
            self._hash = sha1_hash.digest()
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
