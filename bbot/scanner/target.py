import logging
import regex as re
from radixtarget import RadixTarget
from radixtarget import host_size_key


def _fnv1a_64(data_strings):
    """FNV-1a 64-bit hash over sorted strings. Deterministic, pure Python."""
    h = 0xCBF29CE484222325
    for s in data_strings:
        for b in s.encode():
            h ^= b
            h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


from bbot.errors import *
from bbot.core.event import is_event
from bbot.core.event.helpers import EventSeed, BaseEventSeed
from bbot.core.helpers.misc import is_dns_name, is_ip, is_ip_type, strip_comments

log = logging.getLogger("bbot.core.target")


def _host_str(value):
    """Extract a plain host string from any BBOT input type.

    Handles events, EventSeeds, ipaddress objects, and complex strings (URLs, emails, host:port).
    Returns None if no host can be extracted.
    """
    if value is None:
        return None
    if is_event(value) or isinstance(value, BaseEventSeed):
        h = value.host
        return str(h) if h else None
    if is_ip(value, include_network=True) or is_dns_name(value):
        return str(value)
    if isinstance(value, str):
        try:
            event_seed = EventSeed(value)
            h = event_seed.host
            return str(h) if h else None
        except ValidationError:
            return None
    return None


class BaseTarget:
    """
    A collection of BBOT events that represent a scan target.

    Uses a RadixTarget internally for fast scope lookups, and layers on
    BBOT-specific parsing (events, URLs, emails, host:port) and hashing.

    This class is inherited by all three components of the BBOT target:
        - Target
        - Blacklist
        - Seeds
    """

    accept_target_types = ["TARGET"]

    def __init__(self, *targets, strict_scope=False, acl_mode=False):
        # strip comments and ignore blank targets
        targets = [stripped for t in targets if (stripped := (strip_comments(t).strip() if isinstance(t, str) else t))]
        self.strict_scope = strict_scope
        self._rt = RadixTarget(strict_scope=strict_scope, acl_mode=acl_mode)
        self.event_seeds = set()
        if targets:
            self.add(list(targets))

    @property
    def inputs(self):
        return set(e.input for e in self.event_seeds)

    @property
    def hosts(self):
        return set(self._rt.hosts)

    @property
    def hash(self):
        h = self._rt.hash
        if self.strict_scope:
            h ^= 1
        return h.to_bytes(8, "big", signed=True)

    def get(self, event, **kwargs):
        """Look up a host in the radix tree.

        Accepts events, URLs, emails, host:port strings, IPs, CIDRs, and hostnames.
        Returns the stored data for the matching host, or None.
        """
        raise_error = kwargs.get("raise_error", False)
        host_str = _host_str(event)
        if host_str is None:
            if raise_error:
                raise KeyError(f"Host not found: '{event}'")
            return None
        return self._rt.get(host_str)

    def add(self, targets, data=None):
        if not isinstance(targets, (list, set, tuple)):
            targets = [targets]
        event_seeds = set()
        for target in targets:
            # accept pre-parsed EventSeed objects to avoid expensive re-parsing
            if isinstance(target, BaseEventSeed):
                event_seed = target
            else:
                event_seed = EventSeed(target)
            if not event_seed._target_type in self.accept_target_types:
                log.warning(f"Invalid target type for {self.__class__.__name__}: {event_seed.type}")
                continue
            event_seeds.add(event_seed)

        # sort by host size to ensure consistency
        event_seeds = sorted(event_seeds, key=lambda e: (0, 0) if not e.host else host_size_key(str(e.host)))
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
        """Insert a host into the radix tree.

        The radix tree cannot handle host == None, but some subclasses (e.g. ScanBlacklist)
        need to receive non-host-based entries such as BLACKLIST_REGEX. BaseTarget.add()
        always calls self._add(); this default implementation safely ignores hostless
        entries while still delegating normal hosts to the radix tree.
        """
        if host is None:
            return
        self._rt.insert(str(host), data=data)

    # RFC 2317 classless reverse delegation names contain "/" in their labels
    # (e.g. "207.128/25.38.186.64.in-addr.arpa").  These are valid DNS wire
    # names but fail hostname validation.  Hickory-DNS may also backslash-
    # escape the slash in presentation format ("128\/25").
    _rfc2317_re = re.compile(r"[/\\].*\.in-addr\.arpa$|[/\\].*\.ip6\.arpa$", re.IGNORECASE)

    def _make_event_seed(self, target, raise_error=False):
        try:
            return EventSeed(target)
        except ValidationError:
            import traceback

            msg = f"Invalid target: '{target}'"
            if raise_error:
                raise KeyError(msg)
            elif self._rfc2317_re.search(str(target)):
                log.verbose(f"Skipping RFC 2317 classless delegation name: '{target}'")
            else:
                log.warning(msg)
                log.trace("".join(traceback.format_stack()))

    def __contains__(self, other):
        if isinstance(other, BaseTarget):
            for h in other.hosts:
                if self.get(str(h)) is None:
                    return False
            return True
        try:
            return self.get(other) is not None
        except (ValueError, TypeError):
            return False

    def __iter__(self):
        yield from self.event_seeds

    def __len__(self):
        return len(self._rt)

    def __bool__(self):
        return bool(len(self._rt)) or bool(self.event_seeds)

    def __eq__(self, other):
        return self.hash == getattr(other, "hash", None)

    def __hash__(self):
        return hash(self.hash)


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
            existing = self.get(str(host), raise_error=False, single=False)
            if existing is not None:
                existing.add(data)
                event_set = existing
            else:
                event_set = {data}
            super()._add(host, data=event_set)

    @property
    def hash(self):
        """Seeds get hashed by event data, not by hosts."""
        h = _fnv1a_64(sorted(str(e.data) for e in self.event_seeds))
        return h.to_bytes(8, "big")


class ACLTarget(BaseTarget):
    def __init__(self, *args, **kwargs):
        # acl_mode deduplicates (parent absorbs child), but it's mutually exclusive
        # with strict_scope in radixtarget 4.x. When strict_scope is enabled,
        # we skip acl_mode — DNS entries need to remain separate for exact matching,
        # and IP range dedup is handled naturally by the radix tree.
        if not kwargs.get("strict_scope", False):
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
            if event_seed is not None:
                host = event_seed.host
                to_match = event_seed.data
            else:
                to_match = str(host)
        except ValidationError:
            to_match = str(host)
        event_result = super().get(host)
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

    @property
    def hash(self):
        """Blacklist hash includes both hosts and regex patterns."""
        h = (self._rt.hash ^ _fnv1a_64(sorted(r.pattern for r in self.blacklist_regexes))) & 0xFFFFFFFFFFFFFFFF
        return h.to_bytes(8, "big")

    def __len__(self):
        return len(self._rt) + len(self.blacklist_regexes)

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

    def __init__(self, seeds=None, target=None, blacklist=None, strict_scope=False):
        self.strict_scope = strict_scope
        self._orig_seeds = seeds

        target_list = list(target) if target else []
        self.target = ScanTarget(*target_list, strict_scope=strict_scope)

        # Seeds are only copied from target if target is defined but seeds are NOT defined
        # Pass pre-parsed event_seeds to avoid expensive re-parsing of every target string
        if seeds is None:
            seeds = list(self.target.event_seeds)
        self.seeds = ScanSeeds(*list(seeds), strict_scope=strict_scope)

        blacklist_list = list(blacklist) if blacklist else []
        self.blacklist = ScanBlacklist(*blacklist_list)

    @property
    def json(self):
        j = {
            "target": sorted(self.target.inputs),
            "blacklist": sorted(self.blacklist.inputs),
            "strict_scope": self.strict_scope,
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
        return b"".join(t.hash for t in (self.seeds, self.target, self.blacklist))

    @property
    def scope_hash(self):
        return b"".join(t.hash for t in (self.target, self.blacklist))

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
        if self.blacklisted(host):
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
        return self.blacklist.get(host) is not None

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
        return self.target.get(host) is not None

    def __eq__(self, other):
        return self.hash == other.hash

    async def generate_children(self, helpers):
        """
        Generate children for the target, for seed types that expand into other seed types.
        E.g. ASN targets are expanded into their constituent IP ranges.
        """
        # If the user explicitly set a narrower target scope than their seeds
        # (e.g. `-t evilcorp.com -s AS1234`), don't widen the target with expanded seeds
        has_explicit_scope = set(self.target.inputs) != set(self.seeds.inputs)

        # Expand seeds first
        for event_seed in list(self.seeds.event_seeds):
            children = await event_seed._generate_children(helpers=helpers)
            for child in children:
                self.seeds.add(child)

        # Also expand blacklist event seeds (like ASN targets)
        for event_seed in list(self.blacklist.event_seeds):
            children = await event_seed._generate_children(helpers=helpers)
            for child in children:
                self.blacklist.add(child)

        # Widen target scope to include expanded seed hosts (e.g. IP ranges from ASN),
        # but only when seeds and target were originally the same
        if not has_explicit_scope:
            expanded_seed_hosts = set(self.seeds.hosts)
            for host in expanded_seed_hosts:
                if host not in self.target:
                    self.target.add(host)
