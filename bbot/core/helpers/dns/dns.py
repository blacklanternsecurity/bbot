import dns
import logging
import dns.exception
import dns.asyncresolver
from radixtarget import RadixTarget

from bbot.errors import DNSError
from bbot.core.engine import EngineClient
from ..misc import clean_dns_record, is_ip, is_domain, is_dns_name

from .engine import DNSEngine

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper(EngineClient):

    SERVER_CLASS = DNSEngine
    ERROR_CLASS = DNSError

    """Helper class for DNS-related operations within BBOT.

    This class provides mechanisms for host resolution, wildcard domain detection, event tagging, and more.
    It centralizes all DNS-related activities in BBOT, offering both synchronous and asynchronous methods
    for DNS resolution, as well as various utilities for batch resolution and DNS query filtering.

    Attributes:
        parent_helper: A reference to the instantiated `ConfigAwareHelper` (typically `scan.helpers`).
        resolver (BBOTAsyncResolver): An asynchronous DNS resolver tailored for BBOT with rate-limiting capabilities.
        timeout (int): The timeout value for DNS queries. Defaults to 5 seconds.
        retries (int): The number of retries for failed DNS queries. Defaults to 1.
        abort_threshold (int): The threshold for aborting after consecutive failed queries. Defaults to 50.
        runaway_limit (int): Maximum allowed distance for consecutive DNS resolutions. Defaults to 5.
        all_rdtypes (list): A list of DNS record types to be considered during operations.
        wildcard_ignore (tuple): Domains to be ignored during wildcard detection.
        wildcard_tests (int): Number of tests to be run for wildcard detection. Defaults to 5.
        _wildcard_cache (dict): Cache for wildcard detection results.
        _dns_cache (LRUCache): Cache for DNS resolution results, limited in size.
        resolver_file (Path): File containing system's current resolver nameservers.
        filter_bad_ptrs (bool): Whether to filter out DNS names that appear to be auto-generated PTR records. Defaults to True.

    Args:
        parent_helper: The parent helper object with configuration details and utilities.

    Raises:
        DNSError: If an issue arises when creating the BBOTAsyncResolver instance.

    Examples:
        >>> dns_helper = DNSHelper(parent_config)
        >>> resolved_host = dns_helper.resolver.resolve("example.com")
    """

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.config = self.parent_helper.config
        self.dns_config = self.config.get("dns", {})
        super().__init__(server_kwargs={"config": self.config})

        # resolver
        self.timeout = self.dns_config.get("timeout", 5)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.rotate = True
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

        self.runaway_limit = self.config.get("runaway_limit", 5)

        # wildcard handling
        self.wildcard_disable = self.dns_config.get("wildcard_disable", False)
        self.wildcard_ignore = RadixTarget()
        for d in self.dns_config.get("wildcard_ignore", []):
            self.wildcard_ignore.insert(d)

        # copy the system's current resolvers to a text file for tool use
        self.system_resolvers = dns.resolver.Resolver().nameservers
        # TODO: DNS server speed test (start in background task)
        self.resolver_file = self.parent_helper.tempfile(self.system_resolvers, pipe=False)

        # brute force helper
        self._brute = None

    async def resolve(self, query, **kwargs):
        return await self.run_and_return("resolve", query=query, **kwargs)

    async def resolve_raw(self, query, **kwargs):
        return await self.run_and_return("resolve_raw", query=query, **kwargs)

    async def resolve_batch(self, queries, **kwargs):
        agen = self.run_and_yield("resolve_batch", queries=queries, **kwargs)
        while 1:
            try:
                yield await agen.__anext__()
            except (StopAsyncIteration, GeneratorExit):
                await agen.aclose()
                break

    async def resolve_raw_batch(self, queries):
        agen = self.run_and_yield("resolve_raw_batch", queries=queries)
        while 1:
            try:
                yield await agen.__anext__()
            except (StopAsyncIteration, GeneratorExit):
                await agen.aclose()
                break

    @property
    def brute(self):
        if self._brute is None:
            from .brute import DNSBrute

            self._brute = DNSBrute(self.parent_helper)
        return self._brute

    async def is_wildcard(self, query, dns_children=None, rdtype=None):
        if [dns_children, rdtype].count(None) == 1:
            raise ValueError("Both dns_children and rdtype must be specified")

        query = self._wildcard_prevalidation(query)
        if not query:
            return {}

        # skip check if the query is a domain
        if is_domain(query):
            return {}

        return await self.run_and_return("is_wildcard", query=query, dns_children=dns_children, rdtype=rdtype)

    async def is_wildcard_domain(self, domain, dns_children=None, log_info=False):
        domain = self._wildcard_prevalidation(domain)
        if not domain:
            return {}

        return await self.run_and_return("is_wildcard_domain", domain=domain, dns_children=dns_children, log_info=False)

    def _wildcard_prevalidation(self, host):
        if self.wildcard_disable:
            return False

        host = clean_dns_record(host)
        # skip check if it's an IP or a plain hostname
        if is_ip(host) or not "." in host:
            return False

        # skip if query isn't a dns name
        if not is_dns_name(host):
            return False

        # skip check if the query's parent domain is excluded in the config
        wildcard_ignore = self.wildcard_ignore.search(host)
        if wildcard_ignore:
            log.debug(f"Skipping wildcard detection on {host} because {wildcard_ignore} is excluded in the config")
            return False

        return host

    async def _mock_dns(self, mock_data):
        from .mock import MockResolver

        self.resolver = MockResolver(mock_data)
        await self.run_and_return("_mock_dns", mock_data=mock_data)
