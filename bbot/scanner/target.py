import logging
import regex as re
from hashlib import sha1
from radixtarget import RadixTarget
from radixtarget.helpers import host_size_key

from bbot.errors import *
from bbot.core.event import is_event
from bbot.core.event.helpers import EventSeed, BaseEventSeed
from bbot.core.helpers.misc import is_dns_name, is_ip, is_ip_type

log = logging.getLogger("bbot.core.target")


class BaseTarget(RadixTarget):
    """
    A collection of BBOT events that represent a scan target.

    The purpose of this class is to hold a potentially huge target list in a space-efficient way,
    while allowing lightning fast scope lookups.

    This class is inherited by all three components of the BBOT target:
        - Target
        - Blacklist
        - Seeds
    """

    accept_target_types = ["TARGET"]

    def __init__(self, *targets, **kwargs):
        # ignore blank targets (sometimes happens as a symptom of .splitlines())
        targets = [stripped for t in targets if (stripped := (t.strip() if isinstance(t, str) else t))]
        self.event_seeds = set()
        super().__init__(*targets, **kwargs)

    @property
    def inputs(self):
        return set(e.input for e in self.event_seeds)

    def get(self, event, **kwargs):
        """
        Here we override RadixTarget's get() method, which normally only accepts hosts, to also accept events for convenience.
        """
        host = None
        raise_error = kwargs.get("raise_error", False)
        # if it's already an event or event seed, use its host
        if is_event(event) or isinstance(event, BaseEventSeed):
            host = event.host
        # save resources by checking if the event is an IP or DNS name
        elif is_ip(event, include_network=True) or is_dns_name(event):
            host = event
        # if it's a string, autodetect its type and parse out its host
        elif isinstance(event, str):
            event_seed = self._make_event_seed(event, raise_error=raise_error)
            host = event_seed.host
            if not host:
                return
        else:
            raise ValueError(f"Invalid target type for {self.__class__.__name__}: {type(event)}")
        if not host:
            msg = f"Host not found: '{event}'"
            if raise_error:
                raise KeyError(msg)
            else:
                log.warning(msg)
                return
        results = super().get(host, **kwargs)
        return results

    def _make_event_seed(self, target, raise_error=False):
        try:
            return EventSeed(target)
        except ValidationError:
            msg = f"Invalid target: '{target}'"
            if raise_error:
                raise KeyError(msg)
            else:
                log.warning(msg)

    def add(self, targets, data=None):
        if not isinstance(targets, (list, set, tuple)):
            targets = [targets]
        event_seeds = set()
        for target in targets:
            event_seed = EventSeed(target)
            if not event_seed._target_type in self.accept_target_types:
                log.warning(f"Invalid target type for {self.__class__.__name__}: {event_seed.type}")
                continue
            event_seeds.add(event_seed)

        # sort by host size to ensure consistency
        event_seeds = sorted(event_seeds, key=lambda e: (0, 0) if not e.host else host_size_key(e.host))
        for event_seed in event_seeds:
            self.event_seeds.add(event_seed)
            # Some event seeds (e.g. ORG_STUB, USERNAME, BLACKLIST_REGEX) are not host-based and have
            # host == None. These are still useful as parsed target entries, but cannot always be
            # represented in the underlying RadixTarget tree, which expects a concrete host.
            # Subclasses like ScanBlacklist may still need to see these entries (for regex handling,
            # etc.), so we always call self._add() and let the subclass decide whether to forward to
            # the radix layer.
            self._add(event_seed.host, data=(event_seed if data is None else data))

    def _add(self, host, data):
        """
        Wrapper around RadixTarget._add().

        The radix tree cannot handle host == None, but some subclasses (e.g. ScanBlacklist)
        need to receive non-host-based entries such as BLACKLIST_REGEX. BaseTarget.add()
        always calls self._add(); this default implementation safely ignores hostless
        entries while still delegating normal hosts to the underlying RadixTarget.
        """
        if host is None:
            return
        super()._add(host, data)

    def __iter__(self):
        yield from self.event_seeds


class ScanSeeds(BaseTarget):
    """
    Initial events used to seed a scan.

    These are the seeds specified by the user, e.g. via `-s` on the CLI.
    If no seeds were specified, the targets (`-t`) are copied here.
    """

    def get(self, event, single=True, **kwargs):
        results = super().get(event, **kwargs)
        if results and single:
            return next(iter(results))
        return results

    def _add(self, host, data):
        """
        Overrides the base method to enable having multiple events for the same host.

        The "data" attribute of the node is now a set of events.

        This is useful for seeds, because it lets us have both evilcorp.com:80 and https://evilcorp.com
            as separate events even though they have the same host.
        """
        if host:
            try:
                event_set = self.get(host, raise_error=True, single=False)
                event_set.add(data)
            except KeyError:
                event_set = {data}
            super()._add(host, data=event_set)

    def _hash_value(self):
        # seeds get hashed by event data
        return sorted(str(e.data).encode() for e in self.event_seeds)


class ACLTarget(BaseTarget):
    def __init__(self, *args, **kwargs):
        # ACL mode dedupes by host (and skips adding already-contained hosts) for efficiency
        kwargs["acl_mode"] = True
        super().__init__(*args, **kwargs)


class ScanTarget(ACLTarget):
    """
    A collection of BBOT events that represent a scan's targets.
    """

    pass


class ScanBlacklist(ACLTarget):
    """
    A collection of BBOT events that represent a scan's blacklist.
    """

    accept_target_types = ["TARGET", "BLACKLIST"]

    def __init__(self, *args, **kwargs):
        self.blacklist_regexes = set()
        super().__init__(*args, **kwargs)

    def get(self, host, **kwargs):
        """
        Blacklists only accept IPs or strings. This is cleaner since we need to search for regex patterns.
        """
        if not (is_ip_type(host) or isinstance(host, str)):
            raise ValueError(f"Invalid target type for {self.__class__.__name__}: {type(host)}")
        raise_error = kwargs.get("raise_error", False)
        # first, check event's host against blacklist
        try:
            event_seed = self._make_event_seed(host, raise_error=raise_error)
            host = event_seed.host
            to_match = event_seed.data
        except ValidationError:
            to_match = str(host)
        try:
            event_result = super().get(host, raise_error=True)
        except KeyError:
            event_result = None
        if event_result is not None:
            return event_result
        # next, check event's host against regexes
        for regex in self.blacklist_regexes:
            if regex.search(to_match):
                return host
        if raise_error:
            raise KeyError(f"Host not found: '{host}'")
        return None

    def _add(self, host, data):
        if getattr(data, "type", "") == "BLACKLIST_REGEX":
            self.blacklist_regexes.add(re.compile(data.data))
        if host is not None:
            super()._add(host, data)

    def _hash_value(self):
        # regexes are included in blacklist hash
        regex_patterns = [str(r.pattern).encode() for r in self.blacklist_regexes]
        hosts = [str(h).encode() for h in self.sorted_hosts]
        return hosts + regex_patterns

    def __len__(self):
        return super().__len__() + len(self.blacklist_regexes)

    def __bool__(self):
        return bool(len(self))


class BBOTTarget:
    """
    A convenient abstraction of a scan target that contains three subtargets:
        - seeds
        - target
        - blacklist

    Provides high-level functions like in_scope(), which includes both target and blacklist checks.
    """

    def __init__(self, seeds=None, target=None, blacklist=None, strict_dns_scope=False):
        self.strict_dns_scope = strict_dns_scope
        self._orig_seeds = seeds

        target_list = list(target) if target else []
        self.target = ScanTarget(*target_list, strict_dns_scope=strict_dns_scope)

        # Seeds are only copied from target if target is defined but seeds are NOT defined
        # Use target.inputs (original inputs) to preserve all inputs, including subdomains
        if seeds is None:
            seeds = self.target.inputs
        self.seeds = ScanSeeds(*list(seeds), strict_dns_scope=strict_dns_scope)

        blacklist_list = list(blacklist) if blacklist else []
        self.blacklist = ScanBlacklist(*blacklist_list)

    @property
    def json(self):
        j = {
            "target": sorted(self.target.inputs),
            "blacklist": sorted(self.blacklist.inputs),
            "strict_dns_scope": self.strict_dns_scope,
            "hash": self.hash.hex(),
            "seed_hash": self.seeds.hash.hex(),
            "target_hash": self.target.hash.hex(),
            "blacklist_hash": self.blacklist.hash.hex(),
            "scope_hash": self.scope_hash.hex(),
        }
        if self._orig_seeds is not None:
            j["seeds"] = sorted(self.seeds.inputs)
        return j

    @property
    def hash(self):
        sha1_hash = sha1()
        for target_hash in [t.hash for t in (self.seeds, self.target, self.blacklist)]:
            sha1_hash.update(target_hash)
        return sha1_hash.digest()

    @property
    def scope_hash(self):
        sha1_hash = sha1()
        for target_hash in [t.hash for t in (self.target, self.blacklist)]:
            sha1_hash.update(target_hash)
        return sha1_hash.digest()

    def in_scope(self, host):
        """
        Check whether a hostname, url, IP, etc. is in scope.
        Accepts either events or string data.

        This method checks both target AND blacklist.
        A host is in-scope if it is in the target AND not blacklisted.

        Note: This is different from `in_target()` which only checks the target.
        - `in_target()`: checks if host is in the target
        - `in_scope()`: checks if host is in the target AND not blacklisted

        Examples:
            Check if a URL is in scope:
            >>> preset.in_scope("http://www.evilcorp.com")
            True
        """
        blacklisted = self.blacklisted(host)
        if blacklisted:
            return False
        return self.in_target(host)

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
        return host in self.blacklist

    def in_target(self, host):
        """
        Check whether a hostname, url, IP, etc. is in the target.

        This method ONLY checks the target, NOT the blacklist.
        Use `in_scope()` to check both target AND blacklist.

        Note that `host` can be a hostname, IP address, CIDR, email address, or any BBOT `Event` with the `host` attribute.

        Args:
            host (str or IPAddress or Event): The host to check against the target

        Examples:
            Check if a URL's host is in target:
            >>> preset.in_target("http://www.evilcorp.com")
            True
        """
        return host in self.target

    def __eq__(self, other):
        return self.hash == other.hash
