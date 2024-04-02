import dns
import logging
import dns.exception
import dns.asyncresolver
from contextlib import suppress

from bbot.core.engine import EngineClient
from bbot.core.errors import ValidationError
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
        _event_cache (LRUCache): Cache for event resolution results, tags. Limited in size.
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

    async def resolve_custom_batch(self, queries):
        async for _ in self.run_and_yield("resolve_custom_batch", queries=queries):
            yield _

    async def resolve_event(self, event, minimal=False):
        # abort if the event doesn't have a host
        if (not event.host) or (event.type in ("IP_RANGE",)):
            # tags, whitelisted, blacklisted, children
            return set(), False, False, dict()

        event_host = str(event.host)
        event_type = str(event.type)
        kwargs = {"event_host": event_host, "event_type": event_type, "minimal": minimal}
        event_tags, dns_children = await self.run_and_return("resolve_event", **kwargs)

        # whitelisting / blacklisting based on resolved hosts
        event_whitelisted = False
        event_blacklisted = False
        for rdtype, children in dns_children.items():
            for host in children:
                if rdtype in ("A", "AAAA", "CNAME"):
                    # having a CNAME to an in-scope resource doesn't make you in-scope
                    if rdtype != "CNAME":
                        with suppress(ValidationError):
                            if self.parent_helper.scan.whitelisted(host):
                                self.log.critical(f"{event_host} --> {host} is whitelisted")
                                event_whitelisted = True
                    # CNAME to a blacklisted resources, means you're blacklisted
                    with suppress(ValidationError):
                        if self.parent_helper.scan.blacklisted(host):
                            self.log.critical(f"{event_host} --> {host} is blacklisted")
                            event_blacklisted = True

        return event_tags, event_whitelisted, event_blacklisted, dns_children

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

        # skip if query isn't a dns name
        if not is_dns_name(query):
            return {}

        # skip check if the query's parent domain is excluded in the config
        for d in self.wildcard_ignore:
            if host_in_host(query, d):
                log.debug(f"Skipping wildcard detection on {query} because it is excluded in the config")
                return {}

        query = clean_dns_record(query)
        # skip check if it's an IP or a plain hostname
        if is_ip(query) or not "." in query:
            return {}
        # skip check if the query is a domain
        if is_domain(query):
            return {}

        return await self.run_and_return("is_wildcard", query=query, ips=ips, rdtype=rdtype)

    async def is_wildcard_domain(self, domain, log_info=False):
        return await self.run_and_return("is_wildcard_domain", domain=domain, log_info=False)

    async def handle_wildcard_event(self, event, children):
        """
        Used within BBOT's scan manager to detect and tag DNS wildcard events.

        Wildcards are detected for every major record type. If a wildcard is detected, its data
        is overwritten, for example: `_wildcard.evilcorp.com`.

        Args:
            event (object): The event to check for wildcards.
            children (list): A list of the event's resulting DNS children after resolution.

        Returns:
            None: This method modifies the `event` in place and does not return a value.

        Examples:
            >>> handle_wildcard_event(event, children)
            # The `event` might now have tags like ["wildcard", "a-wildcard", "aaaa-wildcard"] and
            # its `data` attribute might be modified to "_wildcard.evilcorp.com" if it was detected
            # as a wildcard.
        """
        log.debug(f"Entering handle_wildcard_event({event}, children={children})")
        try:
            event_host = str(event.host)
            # wildcard checks
            if not is_ip(event.host):
                # check if the dns name itself is a wildcard entry
                wildcard_rdtypes = await self.is_wildcard(event_host)
                for rdtype, (is_wildcard, wildcard_host) in wildcard_rdtypes.items():
                    wildcard_tag = "error"
                    if is_wildcard == True:
                        event.add_tag("wildcard")
                        wildcard_tag = "wildcard"
                    event.add_tag(f"{rdtype.lower()}-{wildcard_tag}")

            # wildcard event modification (www.evilcorp.com --> _wildcard.evilcorp.com)
            if not is_ip(event.host) and children:
                if wildcard_rdtypes:
                    # these are the rdtypes that successfully resolve
                    resolved_rdtypes = set([c.upper() for c in children])
                    # these are the rdtypes that have wildcards
                    wildcard_rdtypes_set = set(wildcard_rdtypes)
                    # consider the event a full wildcard if all its records are wildcards
                    event_is_wildcard = False
                    if resolved_rdtypes:
                        event_is_wildcard = all(r in wildcard_rdtypes_set for r in resolved_rdtypes)

                    if event_is_wildcard:
                        if event.type in ("DNS_NAME",) and not "_wildcard" in event.data.split("."):
                            wildcard_parent = self.parent_helper.parent_domain(event_host)
                            for rdtype, (_is_wildcard, _parent_domain) in wildcard_rdtypes.items():
                                if _is_wildcard:
                                    wildcard_parent = _parent_domain
                                    break
                            wildcard_data = f"_wildcard.{wildcard_parent}"
                            if wildcard_data != event.data:
                                log.debug(
                                    f'Wildcard detected, changing event.data "{event.data}" --> "{wildcard_data}"'
                                )
                                event.data = wildcard_data

                # TODO: transplant this
                # tag wildcard domains for convenience
                # elif is_domain(event_host) or hash(event_host) in self._wildcard_cache:
                #     event_target = "target" in event.tags
                #     wildcard_domain_results = await self.is_wildcard_domain(event_host, log_info=event_target)
                #     for hostname, wildcard_domain_rdtypes in wildcard_domain_results.items():
                #         if wildcard_domain_rdtypes:
                #             event.add_tag("wildcard-domain")
                #             for rdtype, ips in wildcard_domain_rdtypes.items():
                #                 event.add_tag(f"{rdtype.lower()}-wildcard-domain")

        finally:
            log.debug(f"Finished handle_wildcard_event({event}, children={children})")

    async def _mock_dns(self, mock_data):
        from .mock import MockResolver

        self.resolver = MockResolver(mock_data)
        await self.run_and_return("_mock_dns", mock_data=mock_data)
