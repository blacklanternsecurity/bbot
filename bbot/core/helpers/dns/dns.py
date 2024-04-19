import dns
import logging
import dns.exception
import dns.asyncresolver

from bbot.core.engine import EngineClient
from ..misc import clean_dns_record, is_ip, is_domain, is_dns_name, host_in_host

from .engine import DNSEngine

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper(EngineClient):

    SERVER_CLASS = DNSEngine

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
        max_dns_resolve_distance (int): Maximum allowed distance for DNS resolution. Defaults to 4.
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
        super().__init__(server_kwargs={"config": self.config})

        # resolver
        self.timeout = self.config.get("dns_timeout", 5)
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.rotate = True
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

        self.max_dns_resolve_distance = self.config.get("max_dns_resolve_distance", 5)

        # wildcard handling
        self.wildcard_disable = self.config.get("dns_wildcard_disable", False)
        self.wildcard_ignore = self.config.get("dns_wildcard_ignore", None)
        if not self.wildcard_ignore:
            self.wildcard_ignore = []
        self.wildcard_ignore = tuple([str(d).strip().lower() for d in self.wildcard_ignore])

        # copy the system's current resolvers to a text file for tool use
        self.system_resolvers = dns.resolver.Resolver().nameservers
        # TODO: DNS server speed test (start in background task)
        self.resolver_file = self.parent_helper.tempfile(self.system_resolvers, pipe=False)

    async def resolve(self, query, **kwargs):
        return await self.run_and_return("resolve", query=query, **kwargs)

    async def resolve_batch(self, queries, **kwargs):
        async for _ in self.run_and_yield("resolve_batch", queries=queries, **kwargs):
            yield _

    async def resolve_raw_batch(self, queries):
        async for _ in self.run_and_yield("resolve_raw_batch", queries=queries):
            yield _

    async def is_wildcard(self, query, ips=None, rdtype=None):
        """
        Use this method to check whether a *host* is a wildcard entry

        This can reliably tell the difference between a valid DNS record and a wildcard within a wildcard domain.

        If you want to know whether a domain is using wildcard DNS, use `is_wildcard_domain()` instead.

        Args:
            query (str): The hostname to check for a wildcard entry.
            ips (list, optional): List of IPs to compare against, typically obtained from a previous DNS resolution of the query.
            rdtype (str, optional): The DNS record type (e.g., "A", "AAAA") to consider during the check.

        Returns:
            dict: A dictionary indicating if the query is a wildcard for each checked DNS record type.
                Keys are DNS record types like "A", "AAAA", etc.
                Values are tuples where the first element is a boolean indicating if the query is a wildcard,
                and the second element is the wildcard parent if it's a wildcard.

        Raises:
            ValueError: If only one of `ips` or `rdtype` is specified or if no valid IPs are specified.

        Examples:
            >>> is_wildcard("www.github.io")
            {"A": (True, "github.io"), "AAAA": (True, "github.io")}

            >>> is_wildcard("www.evilcorp.com", ips=["93.184.216.34"], rdtype="A")
            {"A": (False, "evilcorp.com")}

        Note:
            `is_wildcard` can be True, False, or None (indicating that wildcard detection was inconclusive)
        """
        if [ips, rdtype].count(None) == 1:
            raise ValueError("Both ips and rdtype must be specified")

        query = self._wildcard_prevalidation(query)
        if not query:
            return {}

        # skip check if the query is a domain
        if is_domain(query):
            return {}

        return await self.run_and_return("is_wildcard", query=query, ips=ips, rdtype=rdtype)

    async def is_wildcard_domain(self, domain, log_info=False):
        domain = self._wildcard_prevalidation(domain)
        if not domain:
            return {}

        return await self.run_and_return("is_wildcard_domain", domain=domain, log_info=False)

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
        for d in self.wildcard_ignore:
            if host_in_host(host, d):
                log.debug(f"Skipping wildcard detection on {host} because it is excluded in the config")
                return False

        return host

    async def _mock_dns(self, mock_data):
        from .mock import MockResolver

        self.resolver = MockResolver(mock_data)
        await self.run_and_return("_mock_dns", mock_data=mock_data)