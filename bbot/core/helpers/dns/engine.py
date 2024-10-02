import os
import dns
import time
import asyncio
import logging
import traceback
from cachetools import LRUCache
from contextlib import suppress

from bbot.core.engine import EngineServer
from bbot.core.helpers.async_helpers import NamedLock
from bbot.core.helpers.dns.helpers import extract_targets
from bbot.core.helpers.misc import (
    is_ip,
    rand_string,
    parent_domain,
    domain_parents,
)


log = logging.getLogger("bbot.core.helpers.dns.engine.server")

all_rdtypes = ["A", "AAAA", "SRV", "MX", "NS", "SOA", "CNAME", "TXT"]


class DNSEngine(EngineServer):

    CMDS = {
        0: "resolve",
        1: "resolve_raw",
        2: "resolve_batch",
        3: "resolve_raw_batch",
        4: "is_wildcard",
        5: "is_wildcard_domain",
        99: "_mock_dns",
    }

    def __init__(self, socket_path, config={}, debug=False):
        super().__init__(socket_path, debug=debug)

        self.config = config
        self.dns_config = self.config.get("dns", {})
        # config values
        self.timeout = self.dns_config.get("timeout", 5)
        self.retries = self.dns_config.get("retries", 1)
        self.abort_threshold = self.dns_config.get("abort_threshold", 50)

        # resolver
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.rotate = True
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

        # skip certain queries
        dns_omit_queries = self.dns_config.get("omit_queries", None)
        if not dns_omit_queries:
            dns_omit_queries = []
        self.dns_omit_queries = dict()
        for d in dns_omit_queries:
            d = d.split(":")
            if len(d) == 2:
                rdtype, query = d
                rdtype = rdtype.upper()
                query = query.lower()
                try:
                    self.dns_omit_queries[rdtype].add(query)
                except KeyError:
                    self.dns_omit_queries[rdtype] = {query}

        # wildcard handling
        self.wildcard_ignore = self.dns_config.get("wildcard_ignore", None)
        if not self.wildcard_ignore:
            self.wildcard_ignore = []
        self.wildcard_ignore = tuple([str(d).strip().lower() for d in self.wildcard_ignore])
        self.wildcard_tests = self.dns_config.get("wildcard_tests", 5)
        self._wildcard_cache = dict()
        # since wildcard detection takes some time, This is to prevent multiple
        # modules from kicking off wildcard detection for the same domain at the same time
        self._wildcard_lock = NamedLock()

        self._dns_connectivity_lock = None
        self._last_dns_success = None
        self._last_connectivity_warning = time.time()
        # keeps track of warnings issued for wildcard detection to prevent duplicate warnings
        self._dns_warnings = set()
        self._errors = dict()
        self._debug = self.dns_config.get("debug", False)
        self._dns_cache = LRUCache(maxsize=10000)

        self.filter_bad_ptrs = self.dns_config.get("filter_ptrs", True)

    async def resolve(self, query, **kwargs):
        """Resolve DNS names and IP addresses to their corresponding results.

        This is a high-level function that can translate a given domain name to its associated IP addresses
        or an IP address to its corresponding domain names. It's structured for ease of use within modules
        and will abstract away most of the complexity of DNS resolution, returning a simple set of results.

        Args:
            query (str): The domain name or IP address to resolve.
            **kwargs: Additional arguments to be passed to the resolution process.

        Returns:
            set: A set containing resolved domain names or IP addresses.

        Examples:
            >>> results = await resolve("1.2.3.4")
            {"evilcorp.com"}

            >>> results = await resolve("evilcorp.com")
            {"1.2.3.4", "dead::beef"}
        """
        results = set()
        try:
            answers, errors = await self.resolve_raw(query, **kwargs)
            for answer in answers:
                for _, host in extract_targets(answer):
                    results.add(host)
        except BaseException:
            self.log.trace(f"Caught exception in resolve({query}, {kwargs}):")
            self.log.trace(traceback.format_exc())
            raise

        self.debug(f"Results for {query} with kwargs={kwargs}: {results}")
        return results

    async def resolve_raw(self, query, **kwargs):
        """Resolves the given query to its associated DNS records.

        This function is a foundational method for DNS resolution in this class. It understands both IP addresses and
        hostnames and returns their associated records in a raw format provided by the dnspython library.

        Args:
            query (str): The IP address or hostname to resolve.
            type (str or list[str], optional): Specifies the DNS record type(s) to fetch. Can be a single type like 'A'
                or a list like ['A', 'AAAA']. If set to 'any', 'all', or '*', it fetches all supported types. If not
                specified, the function defaults to fetching 'A' and 'AAAA' records.
            **kwargs: Additional arguments that might be passed to the resolver.

        Returns:
            tuple: A tuple containing two lists:
                - list: A list of tuples where each tuple consists of a record type string (like 'A') and the associated
                  raw dnspython answer.
                - list: A list of tuples where each tuple consists of a record type string and the associated error if
                  there was an issue fetching the record.

        Examples:
            >>> await resolve_raw("8.8.8.8")
            ([('PTR', <dns.resolver.Answer object at 0x7f4a47cdb1d0>)], [])

            >>> await resolve_raw("dns.google")
            (<dns.resolver.Answer object at 0x7f4a47ce46d0>, [])
        """
        # DNS over TCP is more reliable
        # But setting this breaks DNS resolution on Ubuntu because systemd-resolve doesn't support TCP
        # kwargs["tcp"] = True
        try:
            query = str(query).strip()
            kwargs.pop("rdtype", None)
            rdtype = kwargs.pop("type", "A")
            if is_ip(query):
                return await self._resolve_ip(query, **kwargs)
            else:
                return await self._resolve_hostname(query, rdtype=rdtype, **kwargs)
        except BaseException:
            self.log.trace(f"Caught exception in resolve_raw({query}, {kwargs}):")
            self.log.trace(traceback.format_exc())
            raise

    async def _resolve_hostname(self, query, **kwargs):
        """Translate a hostname into its corresponding IP addresses.

        This is the foundational function for converting a domain name into its associated IP addresses. It's designed
        for internal use within the class and handles retries, caching, and a variety of error/timeout scenarios.
        It also respects certain configurations that might ask to skip certain types of queries. Results are returned
        in the default dnspython answer object format.

        Args:
            query (str): The hostname to resolve.
            rdtype (str, optional): The type of DNS record to query (e.g., 'A', 'AAAA'). Defaults to 'A'.
            retries (int, optional): The number of times to retry on failure. Defaults to class-wide `retries`.
            use_cache (bool, optional): Whether to check the cache before trying a fresh resolution. Defaults to True.
            **kwargs: Additional arguments that might be passed to the resolver.

        Returns:
            tuple: A tuple containing:
                - list: A list of resolved IP addresses.
                - list: A list of errors encountered during the resolution process.

        Examples:
            >>> results, errors = await _resolve_hostname("google.com")
            (<dns.resolver.Answer object at 0x7f4a4b2caf50>, [])
        """
        self.debug(f"Resolving {query} with kwargs={kwargs}")
        results = []
        errors = []
        rdtype = kwargs.get("rdtype", "A")

        # skip certain queries if requested
        if rdtype in self.dns_omit_queries:
            if any(h == query or query.endswith(f".{h}") for h in self.dns_omit_queries[rdtype]):
                self.debug(f"Skipping {rdtype}:{query} because it's omitted in the config")
                return results, errors

        parent = parent_domain(query)
        retries = kwargs.pop("retries", self.retries)
        use_cache = kwargs.pop("use_cache", True)
        tries_left = int(retries) + 1
        parent_hash = hash((parent, rdtype))
        dns_cache_hash = hash((query, rdtype))
        while tries_left > 0:
            try:
                if use_cache:
                    results = self._dns_cache.get(dns_cache_hash, [])
                if not results:
                    error_count = self._errors.get(parent_hash, 0)
                    if error_count >= self.abort_threshold:
                        connectivity = await self._connectivity_check()
                        if connectivity:
                            self.log.verbose(
                                f'Aborting query "{query}" because failed {rdtype} queries for "{parent}" ({error_count:,}) exceeded abort threshold ({self.abort_threshold:,})'
                            )
                            if parent_hash not in self._dns_warnings:
                                self.log.verbose(
                                    f'Aborting future {rdtype} queries to "{parent}" because error count ({error_count:,}) exceeded abort threshold ({self.abort_threshold:,})'
                                )
                            self._dns_warnings.add(parent_hash)
                            return results, errors
                    results = await self._catch(self.resolver.resolve, query, **kwargs)
                    if use_cache:
                        self._dns_cache[dns_cache_hash] = results
                    if parent_hash in self._errors:
                        self._errors[parent_hash] = 0
                break
            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.resolver.LifetimeTimeout,
                TimeoutError,
                asyncio.exceptions.TimeoutError,
            ) as e:
                try:
                    self._errors[parent_hash] += 1
                except KeyError:
                    self._errors[parent_hash] = 1
                errors.append(e)
                # don't retry if we get a SERVFAIL
                if isinstance(e, dns.resolver.NoNameservers):
                    break
                tries_left -= 1
                err_msg = (
                    f'DNS error or timeout for {rdtype} query "{query}" ({self._errors[parent_hash]:,} so far): {e}'
                )
                if tries_left > 0:
                    retry_num = (retries + 1) - tries_left
                    self.debug(err_msg)
                    self.debug(f"Retry (#{retry_num}) resolving {query} with kwargs={kwargs}")
                else:
                    self.log.verbose(err_msg)

        if results:
            self._last_dns_success = time.time()
            self.debug(f"Answers for {query} with kwargs={kwargs}: {list(results)}")

        if errors:
            self.debug(f"Errors for {query} with kwargs={kwargs}: {errors}")

        return results, errors

    async def _resolve_ip(self, query, **kwargs):
        """Translate an IP address into a corresponding DNS name.

        This is the most basic function that will convert an IP address into its associated domain name. It handles
        retries, caching, and multiple types of timeout/error scenarios internally. The function is intended for
        internal use and should not be directly called by modules without understanding its intricacies.

        Args:
            query (str): The IP address to be reverse-resolved.
            retries (int, optional): The number of times to retry on failure. Defaults to 0.
            use_cache (bool, optional): Whether to check the cache for the result before attempting resolution. Defaults to True.
            **kwargs: Additional arguments to be passed to the resolution process.

        Returns:
            tuple: A tuple containing:
                - list: A list of resolved domain names (in default dnspython answer format).
                - list: A list of errors encountered during resolution.

        Examples:
            >>> results, errors = await _resolve_ip("8.8.8.8")
            (<dns.resolver.Answer object at 0x7f4a47cdb1d0>, [])
        """
        self.debug(f"Reverse-resolving {query} with kwargs={kwargs}")
        retries = kwargs.pop("retries", 0)
        use_cache = kwargs.pop("use_cache", True)
        tries_left = int(retries) + 1
        results = []
        errors = []
        dns_cache_hash = hash((query, "PTR"))
        while tries_left > 0:
            try:
                if use_cache:
                    results = self._dns_cache.get(dns_cache_hash, [])
                if not results:
                    results = await self._catch(self.resolver.resolve_address, query, **kwargs)
                    if use_cache:
                        self._dns_cache[dns_cache_hash] = results
                break
            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.resolver.LifetimeTimeout,
                TimeoutError,
                asyncio.exceptions.TimeoutError,
            ) as e:
                errors.append(e)
                # don't retry if we get a SERVFAIL
                if isinstance(e, dns.resolver.NoNameservers):
                    self.debug(f"{e} (query={query}, kwargs={kwargs})")
                    break
                else:
                    tries_left -= 1
                    if tries_left > 0:
                        retry_num = (retries + 2) - tries_left
                        self.debug(f"Retrying (#{retry_num}) {query} with kwargs={kwargs}")

        if results:
            self._last_dns_success = time.time()

        return results, errors

    async def resolve_batch(self, queries, threads=10, **kwargs):
        """
        A helper to execute a bunch of DNS requests.

        Args:
            queries (list): List of queries to resolve.
            **kwargs: Additional keyword arguments to pass to `resolve()`.

        Yields:
            tuple: A tuple containing the original query and its resolved value.

        Examples:
            >>> import asyncio
            >>> async def example_usage():
            ...     async for result in resolve_batch(['www.evilcorp.com', 'evilcorp.com']):
            ...         print(result)
            ('www.evilcorp.com', {'1.1.1.1'})
            ('evilcorp.com', {'2.2.2.2'})
        """
        async for (args, _, _), responses in self.task_pool(
            self.resolve, args_kwargs=queries, threads=threads, global_kwargs=kwargs
        ):
            yield args[0], responses

    async def resolve_raw_batch(self, queries, threads=10, **kwargs):
        queries_kwargs = [[q[0], {"type": q[1]}] for q in queries]
        async for (args, kwargs, _), (answers, errors) in self.task_pool(
            self.resolve_raw, args_kwargs=queries_kwargs, threads=threads, global_kwargs=kwargs
        ):
            query = args[0]
            rdtype = kwargs["type"]
            yield ((query, rdtype), (answers, errors))

    async def _catch(self, callback, *args, **kwargs):
        """
        Asynchronously catches exceptions thrown during DNS resolution and logs them.

        This method wraps around a given asynchronous callback function to handle different
        types of DNS exceptions and general exceptions. It logs the exceptions for debugging
        and, in some cases, re-raises them.

        Args:
            callback (callable): The asynchronous function to be executed.
            *args: Positional arguments to pass to the callback.
            **kwargs: Keyword arguments to pass to the callback.

        Returns:
            Any: The return value of the callback function, or an empty list if an exception is caught.

        Raises:
            dns.resolver.NoNameservers: When no nameservers could be reached.
        """
        try:
            return await callback(*args, **kwargs)
        except dns.resolver.NoNameservers:
            raise
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, TimeoutError):
            self.log.debug(f"DNS query with args={args}, kwargs={kwargs} timed out after {self.timeout} seconds")
            raise
        except dns.exception.DNSException as e:
            self.debug(f"{e} (args={args}, kwargs={kwargs})")
        except Exception as e:
            self.log.warning(f"Error in {callback.__qualname__}() with args={args}, kwargs={kwargs}: {e}")
            self.log.trace(traceback.format_exc())
        return []

    async def is_wildcard(self, query, rdtypes, raw_dns_records=None):
        """
        Use this method to check whether a *host* is a wildcard entry

        This can reliably tell the difference between a valid DNS record and a wildcard within a wildcard domain.

        It works by making a bunch of random DNS queries to the parent domain, compiling a list of wildcard IPs,
        then comparing those to the IPs of the host in question. If the host's IP matches the wildcard ones, it's a wildcard.

        If you want to know whether a domain is using wildcard DNS, use `is_wildcard_domain()` instead.

        Args:
            query (str): The hostname to check for a wildcard entry.
            rdtypes (list): The DNS record type (e.g., "A", "AAAA") to consider during the check.
            raw_dns_records (dict, optional): Dictionary of {rdtype: [answer1, answer2, ...], ...} containing raw dnspython answers for the query.

        Returns:
            dict: A dictionary indicating if the query is a wildcard for each checked DNS record type.
                Keys are DNS record types like "A", "AAAA", etc.
                Values are tuples where the first element is a boolean indicating if the query is a wildcard,
                and the second element is the wildcard parent if it's a wildcard.

        Examples:
            >>> is_wildcard("www.github.io", rdtypes=["A", "AAAA", "MX"])
            {"A": (True, "github.io"), "AAAA": (True, "github.io"), "MX": (False, "github.io")}

            >>> is_wildcard("www.evilcorp.com", rdtypes=["A"])
            {"A": (False, "evilcorp.com")}

        Note:
            `is_wildcard` can be True, False, or None (indicating that wildcard detection was inconclusive)
        """
        if isinstance(rdtypes, str):
            rdtypes = [rdtypes]

        result = {}

        # if the work of resolving hasn't been done yet, do it
        if raw_dns_records is None:
            raw_dns_records = {}
            queries = [(query, rdtype) for rdtype in rdtypes]
            async for (_, rdtype), (answers, errors) in self.resolve_raw_batch(queries):
                if answers:
                    for answer in answers:
                        try:
                            raw_dns_records[rdtype].add(answer)
                        except KeyError:
                            raw_dns_records[rdtype] = {answer}
                else:
                    if errors:
                        self.debug(f"Failed to resolve {query} ({rdtype}) during wildcard detection")
                        result[rdtype] = ("ERROR", query)

        # clean + process the raw records into a baseline
        baseline = {}
        baseline_raw = {}
        for rdtype, answers in raw_dns_records.items():
            for answer in answers:
                text_answer = answer.to_text()
                try:
                    baseline_raw[rdtype].add(text_answer)
                except KeyError:
                    baseline_raw[rdtype] = {text_answer}
                for _, host in extract_targets(answer):
                    try:
                        baseline[rdtype].add(host)
                    except KeyError:
                        baseline[rdtype] = {host}

        # if it's unresolved, it's a big nope
        if not raw_dns_records:
            return result

        # once we've resolved the base query and have IP addresses to work with
        # we can compare the IPs to the ones we have on file for wildcards

        # only bother to check the rdypes that actually resolve
        rdtypes_to_check = set(raw_dns_records)

        # for every parent domain, starting with the shortest
        parents = list(domain_parents(query))
        for parent in parents[::-1]:

            # check if the parent domain is set up with wildcards
            wildcard_results = await self.is_wildcard_domain(parent, rdtypes_to_check)

            # for every rdtype
            for rdtype in list(baseline_raw):
                # skip if we already found a wildcard for this rdtype
                if rdtype in result:
                    continue

                # get our baseline IPs from above
                _baseline = baseline.get(rdtype, set())
                _baseline_raw = baseline_raw.get(rdtype, set())

                wildcard_rdtypes = wildcard_results.get(parent, {})
                wildcards = wildcard_rdtypes.get(rdtype, None)
                if wildcards is None:
                    continue
                wildcards, wildcard_raw = wildcards

                if wildcard_raw:
                    # skip this rdtype from now on
                    rdtypes_to_check.remove(rdtype)

                    # check if any of our baseline IPs are in the wildcard results
                    is_wildcard = any(r in wildcards for r in _baseline)
                    is_wildcard_raw = any(r in wildcard_raw for r in _baseline_raw)

                    # if there are any matches, we have a wildcard
                    if is_wildcard or is_wildcard_raw:
                        result[rdtype] = (True, parent)
                    else:
                        # otherwise, it's still suspicious, because we had random stuff resolve at this level
                        result[rdtype] = ("POSSIBLE", parent)

        # any rdtype that wasn't a wildcard, mark it as False
        for rdtype, answers in baseline_raw.items():
            if answers and rdtype not in result:
                result[rdtype] = (False, query)

        return result

    async def is_wildcard_domain(self, domain, rdtypes):
        """
        Check whether a given host or its children make use of wildcard DNS entries. Wildcard DNS can have
        various implications, particularly in subdomain enumeration and subdomain takeovers.

        Args:
            domain (str): The domain to check for wildcard DNS entries.
            rdtypes (list): Which DNS record types to check.

        Returns:
            dict: A dictionary where the keys are the parent domains that have wildcard DNS entries,
            and the values are another dictionary of DNS record types ("A", "AAAA", etc.) mapped to
            sets of their resolved IP addresses.

        Examples:
            >>> is_wildcard_domain("github.io")
            {"github.io": {"A": {"1.2.3.4"}, "AAAA": {"dead::beef"}}}

            >>> is_wildcard_domain("example.com")
            {}
        """
        if isinstance(rdtypes, str):
            rdtypes = [rdtypes]
        rdtypes = set(rdtypes)

        wildcard_results = {}
        # make a list of its parents
        parents = list(domain_parents(domain, include_self=True))
        # and check each of them, beginning with the highest parent (i.e. the root domain)
        for i, host in enumerate(parents[::-1]):
            host_results = {}
            queries = [((host, rdtype), {}) for rdtype in rdtypes]
            async for ((_, rdtype), _, _), (results, results_raw) in self.task_pool(
                self._is_wildcard_zone, args_kwargs=queries
            ):
                # if we hit a wildcard, we can skip this rdtype from now on
                if results_raw:
                    rdtypes.remove(rdtype)
                    host_results[rdtype] = results, results_raw

            if host_results:
                wildcard_results[host] = host_results

        return wildcard_results

    async def _is_wildcard_zone(self, host, rdtype):
        """
        Check whether a specific DNS zone+rdtype has a wildcard configuration
        """
        rdtype = rdtype.upper()

        # have we checked this host before?
        host_hash = hash((host, rdtype))
        async with self._wildcard_lock.lock(host_hash):
            # if we've seen this host before
            try:
                wildcard_results, wildcard_results_raw = self._wildcard_cache[host_hash]
                self.debug(f"Got {host}:{rdtype} from cache")
            except KeyError:
                wildcard_results = set()
                wildcard_results_raw = set()
                self.debug(f"Checking if {host}:{rdtype} is a wildcard")

                # determine if this is a wildcard domain
                # resolve a bunch of random subdomains of the same parent
                rand_queries = []
                for _ in range(self.wildcard_tests):
                    rand_query = f"{rand_string(digits=False, length=10)}.{host}"
                    rand_queries.append((rand_query, rdtype))

                async for (query, rdtype), (answers, errors) in self.resolve_raw_batch(rand_queries, use_cache=False):
                    for answer in answers:
                        # consider both the raw record
                        wildcard_results_raw.add(answer.to_text())
                        # and all the extracted hosts
                        for _, t in extract_targets(answer):
                            wildcard_results.add(t)

                if wildcard_results:
                    self.log.info(f"Encountered domain with wildcard DNS ({rdtype}): *.{host}")
                else:
                    self.debug(f"Finished checking {host}:{rdtype}, it is not a wildcard")
                self._wildcard_cache[host_hash] = wildcard_results, wildcard_results_raw

        return wildcard_results, wildcard_results_raw

    async def _is_wildcard(self, query, rdtypes, dns_children):
        if isinstance(rdtypes, str):
            rdtypes = [rdtypes]

    @property
    def dns_connectivity_lock(self):
        if self._dns_connectivity_lock is None:
            self._dns_connectivity_lock = asyncio.Lock()
        return self._dns_connectivity_lock

    async def _connectivity_check(self, interval=5):
        """
        Periodically checks for an active internet connection by attempting DNS resolution.

        Args:
            interval (int, optional): The time interval, in seconds, at which to perform the check.
            Defaults to 5 seconds.

        Returns:
            bool: True if there is an active internet connection, False otherwise.

        Examples:
            >>> await _connectivity_check()
            True
        """
        if self._last_dns_success is not None:
            if time.time() - self._last_dns_success < interval:
                return True
        dns_server_working = []
        async with self.dns_connectivity_lock:
            with suppress(Exception):
                dns_server_working = await self._catch(self.resolver.resolve, "www.google.com", rdtype="A")
                if dns_server_working:
                    self._last_dns_success = time.time()
                    return True
        if time.time() - self._last_connectivity_warning > interval:
            self.log.warning(f"DNS queries are failing, please check your internet connection")
            self._last_connectivity_warning = time.time()
        self._errors.clear()
        return False

    def debug(self, *args, **kwargs):
        if self._debug:
            self.log.trace(*args, **kwargs)

    @property
    def in_tests(self):
        return os.getenv("BBOT_TESTING", "") == "True"

    async def _mock_dns(self, mock_data, custom_lookup_fn=None):
        from .mock import MockResolver

        def deserialize_function(func_source):
            assert self.in_tests, "Can only mock when BBOT_TESTING=True"
            if func_source is None:
                return None
            exec(func_source)
            return locals()["custom_lookup"]

        self.resolver = MockResolver(mock_data, custom_lookup_fn=deserialize_function(custom_lookup_fn))
