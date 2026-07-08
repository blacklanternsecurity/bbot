import asyncio
import logging
import time
from contextlib import suppress

from cachetools import LFUCache, LRUCache
from radixtarget import RadixTarget

from blastdns import Client, ClientConfig, DNSError, DNSResult, MockClient, get_system_resolvers
from blastdns.exceptions import BlastDNSError

from bbot.core.helpers.async_helpers import NamedLock, async_cachedmethod
from .helpers import all_rdtypes, extract_targets, record_to_text
from ..misc import clean_dns_record, domain_parents, is_dns_name, is_domain, is_ip, parent_domain, rand_string

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """Helper class for DNS-related operations within BBOT.

    Wraps the blastdns ``Client`` (a Rust-backed async DNS engine) and adds the
    BBOT-specific concerns that live above raw resolution: wildcard detection,
    per-zone error tracking, connectivity checks, and ``dns_omit_queries``
    filtering.

    Attributes:
        parent_helper: A reference to the instantiated `ConfigAwareHelper` (typically `scan.helpers`).
        blastdns (blastdns.Client): The underlying Rust DNS client.
        timeout (int): Per-query timeout in seconds. Defaults to 5.
        retries (int): Number of retries for failed DNS queries. Defaults to 5.
        abort_threshold (int): Consecutive failed queries per parent before aborting. Defaults to 50.
        wildcard_ignore (RadixTarget): Domains to skip during wildcard detection.
        wildcard_tests (int): Random subdomains generated per wildcard check. Defaults to 5.
        resolver_file (Path): File containing the system's resolver IPs (for tools that need it).
    """

    def __init__(self, parent_helper):
        self.log = log
        self.parent_helper = parent_helper
        self.config = self.parent_helper.config
        self.dns_config = self.config.get("dns", {})

        # config
        self.timeout = self.dns_config.get("timeout", 5)
        self.retries = self.dns_config.get("retries", 5)
        self.threads = self.dns_config.get("threads", 5)
        self.cache_size = self.dns_config.get("cache_size", 10000)
        self.abort_threshold = self.dns_config.get("abort_threshold", 50)
        # how many consecutive DNS resolution hops we allow before tagging an event as runaway
        self.runaway_limit = self.dns_config.get("runaway_limit", 5)

        # blastdns client
        self.system_resolvers = get_system_resolvers()
        self.log.debug(
            f"Starting BlastDNS client with {self.threads} threads per resolver, "
            f"{self.retries} retries, {self.cache_size} cache size, "
            f"and {self.timeout} second timeout"
        )
        self.blastdns = Client(
            self.system_resolvers,
            ClientConfig(
                request_timeout_ms=self.timeout * 1000,
                max_retries=self.retries,
                threads_per_resolver=self.threads,
                cache_capacity=self.cache_size,
            ),
        )

        # parse dns.omit_queries (e.g. "A:internal.bad.com") into {rdtype: {host, ...}}
        self.dns_omit_queries = {}
        for entry in self.dns_config.get("omit_queries", None) or []:
            parts = entry.split(":")
            if len(parts) == 2:
                rdtype, host = parts
                self.dns_omit_queries.setdefault(rdtype.upper(), set()).add(host.lower())

        # wildcard handling
        self.wildcard_disable = self.dns_config.get("wildcard_disable", False)
        self.wildcard_tests = self.dns_config.get("wildcard_tests", 5)
        self.wildcard_ignore = RadixTarget()
        for d in self.dns_config.get("wildcard_ignore", []):
            self.wildcard_ignore.insert(d)
        self._wildcard_cache = LRUCache(maxsize=10000)
        self._wildcard_lock = NamedLock()

        # error tracking + connectivity
        self._errors = LRUCache(maxsize=10000)
        self._dns_warnings = LRUCache(maxsize=10000)
        self._dns_connectivity_lock = None
        self._last_dns_success = None
        self._last_connectivity_warning = time.time()

        # copy the system's current resolvers to a text file for tool use
        self.resolver_file = self.parent_helper.tempfile(self.system_resolvers, pipe=False)

        # brute force helper
        self._brute = None

        # method-level dedup caches for is_wildcard / is_wildcard_domain
        self._is_wildcard_cache = LFUCache(maxsize=1000)
        self._is_wildcard_domain_cache = LFUCache(maxsize=1000)

    # ------------------------------------------------------------------
    # Resolution -- thin pass-throughs to blastdns. Anything more complex
    # belongs in a caller that knows the exact shape it wants.
    # ------------------------------------------------------------------

    async def resolve(self, query, rdtype="A"):
        """Resolve to a set of rdata strings (e.g. IPs).

        Returns an empty set on DNS failure (timeout, SERVFAIL, etc).
        """
        try:
            return set(await self.blastdns.resolve(query, rdtype))
        except BlastDNSError as e:
            self.log.debug(f"DNS error resolving {query}/{rdtype}: {e}")
            return set()

    async def resolve_full(self, query, rdtype="A"):
        """Return blastdns ``DNSResult`` (full response with Record objects).

        Returns an empty-answer DNSResult on DNS failure so callers can
        unconditionally iterate ``.response.answers`` without try/except.
        """
        try:
            return await self.blastdns.resolve_full(query, rdtype)
        except BlastDNSError as e:
            self.log.debug(f"DNS error resolving {query}/{rdtype}: {e}")
            return self._empty_result(query)

    async def resolve_multi_full(self, query, rdtypes):
        """Resolve many rdtypes for one host concurrently in Rust.

        Skips rdtypes listed in ``dns_omit_queries`` and rdtypes whose parent
        zone has exceeded ``abort_threshold`` consecutive errors.
        Returns ``dict[rdtype, DNSResult | DNSError]``.
        """
        rdtypes = [r for r in rdtypes if not self._is_omitted(query, r)]
        filtered = []
        for r in rdtypes:
            if not await self._is_aborted(query, r):
                filtered.append(r)
        rdtypes = filtered
        if not rdtypes:
            return {}
        results = await self.blastdns.resolve_multi_full(query, rdtypes)
        # Track per-zone errors so we can circuit-break dead zones
        for rdtype, response in results.items():
            if isinstance(response, DNSError):
                self.record_dns_error(query, rdtype)
            elif isinstance(response, DNSResult) and response.response.answers:
                self.reset_dns_errors(query, rdtype)
        return results

    async def resolve_batch_full(self, hosts, rdtype="A", skip_empty=False, skip_errors=False):
        """Resolve many hosts for one rdtype concurrently in Rust.

        Yields ``(host, DNSResult | DNSError)``.
        """
        async for host, result in self.blastdns.resolve_batch_full(
            hosts, rdtype, skip_empty=skip_empty, skip_errors=skip_errors
        ):
            yield host, result

    def _is_omitted(self, query, rdtype):
        omit_hosts = self.dns_omit_queries.get(rdtype.upper())
        if not omit_hosts:
            return False
        q = str(query).lower()
        return any(q == h or q.endswith(f".{h}") for h in omit_hosts)

    # ------------------------------------------------------------------
    # Wildcard detection
    # ------------------------------------------------------------------

    @async_cachedmethod(
        lambda self: self._is_wildcard_cache,
        key=lambda query, rdtypes, raw_dns_records=None: (query, tuple(sorted(rdtypes)), bool(raw_dns_records)),
    )
    async def is_wildcard(self, query, rdtypes, raw_dns_records=None):
        """
        Check whether ``query`` is a wildcard hit within a wildcard domain.

        Args:
            query (str): The hostname to check.
            rdtypes (list): DNS record types to consider.
            raw_dns_records (dict, optional): ``{rdtype: [Record, ...]}`` already
                resolved for this query. If omitted, the records are fetched.

        Returns:
            dict: ``{rdtype: (is_wildcard, parent)}`` for each rdtype that resolved.
                ``is_wildcard`` may be ``True``, ``False``, ``None``, ``"POSSIBLE"``, or ``"ERROR"``.
        """
        query = self._wildcard_prevalidation(query)
        if not query:
            return {}

        # skip check if the query is itself a domain
        if is_domain(query):
            return {}

        if isinstance(rdtypes, str):
            rdtypes = [rdtypes]

        result = {}

        # if the work of resolving hasn't been done yet, do it
        if raw_dns_records is None:
            raw_dns_records = {}
            multi = await self.resolve_multi_full(query, list(rdtypes))
            for rdtype, response in multi.items():
                if isinstance(response, DNSResult) and response.response.answers:
                    raw_dns_records[rdtype] = response.response.answers
                elif isinstance(response, DNSError):
                    self.log.debug(f"Failed to resolve {query} ({rdtype}) during wildcard detection: {response.error}")
                    result[rdtype] = ("ERROR", query)

        # build the baseline (the IPs/hosts we actually got back for this query)
        baseline = {}
        baseline_raw = {}
        for rdtype, answers in raw_dns_records.items():
            for answer in answers:
                text_answer = record_to_text(answer)
                baseline_raw.setdefault(rdtype, set()).add(text_answer)
                for _, host in extract_targets(answer):
                    baseline.setdefault(rdtype, set()).add(host)

        if not raw_dns_records:
            return result

        rdtypes_to_check = set(raw_dns_records)

        # walk parent domains shortest-first, comparing baseline against any wildcard pool
        parents = list(domain_parents(query))
        for parent in parents[::-1]:
            wildcard_results = await self.is_wildcard_domain(parent, rdtypes_to_check)

            for rdtype in list(baseline_raw):
                if rdtype in result:
                    continue

                _baseline = baseline.get(rdtype, set())
                _baseline_raw = baseline_raw.get(rdtype, set())

                wildcard_rdtypes = wildcard_results.get(parent, {})
                wildcards = wildcard_rdtypes.get(rdtype)
                if wildcards is None:
                    continue
                wildcards, wildcard_raw = wildcards

                if wildcard_raw:
                    rdtypes_to_check.discard(rdtype)
                    is_wc = any(r in wildcards for r in _baseline)
                    is_wc_raw = any(r in wildcard_raw for r in _baseline_raw)
                    if is_wc or is_wc_raw:
                        result[rdtype] = (True, parent)
                    else:
                        result[rdtype] = ("POSSIBLE", parent)

        for rdtype, answers in baseline_raw.items():
            if answers and rdtype not in result:
                result[rdtype] = (False, query)

        return result

    @async_cachedmethod(
        lambda self: self._is_wildcard_domain_cache,
        key=lambda domain, rdtypes: (domain, tuple(sorted(rdtypes))),
    )
    async def is_wildcard_domain(self, domain, rdtypes):
        """For each parent of ``domain``, return the wildcard pool per rdtype.

        Returns ``{parent: {rdtype: (hosts_set, raw_text_set)}}``.
        """
        domain = self._wildcard_prevalidation(domain)
        if not domain:
            return {}

        if isinstance(rdtypes, str):
            rdtypes = [rdtypes]
        rdtypes = set(rdtypes)

        wildcard_results = {}
        # walk parents from shortest (root) to longest, narrowing rdtypes as we find wildcards
        for host in list(domain_parents(domain, include_self=True))[::-1]:
            host_results = {}
            # check each rdtype concurrently for this parent
            tasks = [self._is_wildcard_zone(host, rdtype) for rdtype in list(rdtypes)]
            if not tasks:
                break
            for rdtype, (results, results_raw) in zip(list(rdtypes), await asyncio.gather(*tasks)):
                if results_raw:
                    rdtypes.discard(rdtype)
                    host_results[rdtype] = (results, results_raw)
            if host_results:
                wildcard_results[host] = host_results

        return wildcard_results

    async def _is_wildcard_zone(self, host, rdtype):
        """Test one (host, rdtype) for wildcard configuration. Cached per-pair."""
        rdtype = rdtype.upper()
        host_hash = hash((host, rdtype))

        async with self._wildcard_lock.lock(host_hash):
            try:
                cached = self._wildcard_cache[host_hash]
                self.log.debug(f"Got {host}:{rdtype} from wildcard cache")
                return cached
            except KeyError:
                pass

            self.log.debug(f"Checking if {host}:{rdtype} is a wildcard")
            results = set()
            results_raw = set()

            rand_hosts = [f"{rand_string(digits=False, length=10)}.{host}" for _ in range(self.wildcard_tests)]
            async for _, response in self.resolve_batch_full(rand_hosts, rdtype):
                if not isinstance(response, DNSResult):
                    continue
                for answer in response.response.answers:
                    results_raw.add(record_to_text(answer))
                    for _, t in extract_targets(answer):
                        results.add(t)

            if results:
                self.log.info(f"Encountered domain with wildcard DNS ({rdtype}): *.{host}")
            else:
                self.log.debug(f"Finished checking {host}:{rdtype}, it is not a wildcard")

            self._wildcard_cache[host_hash] = (results, results_raw)
            return results, results_raw

    def _wildcard_prevalidation(self, host):
        if self.wildcard_disable:
            return False

        host = clean_dns_record(host)
        if is_ip(host) or "." not in host:
            return False
        if not is_dns_name(host):
            return False

        wildcard_ignore = self.wildcard_ignore.search(host)
        if wildcard_ignore:
            self.log.debug(
                f"Skipping wildcard detection on {host} because {wildcard_ignore} is excluded in the config"
            )
            return False

        return host

    # ------------------------------------------------------------------
    # Error tracking + connectivity
    # ------------------------------------------------------------------

    async def _is_aborted(self, query, rdtype):
        """Check if queries for this parent zone + rdtype have been circuit-broken.

        Only triggers on sustained timeouts (DNSError), not instant failures
        like NXDOMAIN or SERVFAIL. When the threshold is hit, verifies
        network connectivity first — if the network is down, clears error
        counters instead of aborting (the zone might be fine).
        """
        parent = parent_domain(str(query))
        parent_hash = hash((parent, rdtype))
        error_count = self._errors.get(parent_hash, 0)
        if error_count >= self.abort_threshold:
            # before aborting, make sure our network is actually up
            connectivity = await self._connectivity_check()
            if not connectivity:
                # network is down — don't blame the zone
                self._errors.clear()
                return False
            if parent_hash not in self._dns_warnings:
                self.log.info(
                    f'Aborting {rdtype} queries to "{parent}" — '
                    f"{error_count} consecutive errors exceeded threshold ({self.abort_threshold})"
                )
                self._dns_warnings[parent_hash] = True
            return True
        return False

    def record_dns_error(self, query, rdtype):
        """Bump the error counter for ``query``'s parent zone. Returns the new count."""
        parent_hash = hash((parent_domain(str(query)), rdtype))
        self._errors[parent_hash] = self._errors.get(parent_hash, 0) + 1
        return self._errors[parent_hash]

    def reset_dns_errors(self, query, rdtype):
        parent_hash = hash((parent_domain(str(query)), rdtype))
        if parent_hash in self._errors:
            self._errors[parent_hash] = 0

    @property
    def dns_connectivity_lock(self):
        if self._dns_connectivity_lock is None:
            self._dns_connectivity_lock = asyncio.Lock()
        return self._dns_connectivity_lock

    async def _connectivity_check(self, interval=5):
        """Confirm the network can reach DNS. Cached for ``interval`` seconds."""
        if self._last_dns_success is not None and time.time() - self._last_dns_success < interval:
            return True

        async with self.dns_connectivity_lock:
            with suppress(Exception):
                answers = await self.blastdns.resolve("www.google.com", "A")
                if answers:
                    self._last_dns_success = time.time()
                    return True

        if time.time() - self._last_connectivity_warning > interval:
            self.log.error("DNS queries are failing, please check your internet connection")
            self._last_connectivity_warning = time.time()
        self._errors.clear()
        return False

    # ------------------------------------------------------------------
    # Brute / mock helpers
    # ------------------------------------------------------------------

    @property
    def brute(self):
        if self._brute is None:
            from .brute import DNSBrute

            self._brute = DNSBrute(self.parent_helper)
        return self._brute

    async def _mock_dns(self, mock_data):
        """Swap the underlying client for a ``MockClient`` configured with ``mock_data``."""
        mock_client = MockClient()
        mock_client.mock_dns(mock_data)
        self.blastdns = mock_client

    @staticmethod
    def _empty_result(host=""):
        """Build a minimal ``DNSResult`` with no answers, for use as a safe fallback."""
        from blastdns.models import Header, Response

        header = Header(
            id=0,
            message_type="Response",
            op_code="Query",
            authoritative=False,
            truncation=False,
            recursion_desired=True,
            recursion_available=True,
            authentic_data=False,
            checking_disabled=False,
            response_code="NoError",
            query_count=0,
            answer_count=0,
            name_server_count=0,
            additional_count=0,
        )
        return DNSResult(
            host=host, response=Response(header=header, queries=[], answers=[], name_servers=[], additionals=[])
        )

    async def shutdown(self):
        """No-op kept for API compatibility -- blastdns runs in-process, nothing to tear down."""
        return None


# Re-export for convenience
__all__ = ["DNSHelper", "all_rdtypes", "extract_targets", "record_to_text"]
