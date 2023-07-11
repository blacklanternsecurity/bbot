import asyncio
import logging
import ipaddress
import traceback
import contextlib
import dns.exception
import dns.asyncresolver

from .regexes import dns_name_regex
from bbot.core.helpers.ratelimiter import RateLimiter
from bbot.core.helpers.async_helpers import NamedLock
from bbot.core.errors import ValidationError, DNSError
from .misc import is_ip, is_domain, is_dns_name, domain_parents, parent_domain, rand_string, cloudcheck

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """
    For automatic wildcard detection, nameserver validation, etc.
    """

    all_rdtypes = ["A", "AAAA", "SRV", "MX", "NS", "SOA", "CNAME", "TXT"]

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        try:
            self.resolver = dns.asyncresolver.Resolver()
        except Exception as e:
            raise DNSError(f"Failed to create BBOT DNS resolver: {e}")
        self.timeout = self.parent_helper.config.get("dns_timeout", 5)
        self.retries = self.parent_helper.config.get("dns_retries", 1)
        self.abort_threshold = self.parent_helper.config.get("dns_abort_threshold", 5)
        self.max_dns_resolve_distance = self.parent_helper.config.get("max_dns_resolve_distance", 4)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        self._resolver_list = None

        # skip certain queries
        dns_omit_queries = self.parent_helper.config.get("dns_omit_queries", None)
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

        self.wildcard_ignore = self.parent_helper.config.get("dns_wildcard_ignore", None)
        if not self.wildcard_ignore:
            self.wildcard_ignore = []
        self.wildcard_ignore = tuple([str(d).strip().lower() for d in self.wildcard_ignore])
        self.wildcard_tests = self.parent_helper.config.get("dns_wildcard_tests", 5)
        self._wildcard_cache = dict()
        # since wildcard detection takes some time, This is to prevent multiple
        # modules from kicking off wildcard detection for the same domain at the same time
        self._wildcard_lock = NamedLock()
        # keeps track of warnings issued for wildcard detection to prevent duplicate warnings
        self._dns_warnings = set()
        self._errors = dict()
        self.fallback_nameservers_file = self.parent_helper.wordlist_dir / "nameservers.txt"
        self.dns_queries_per_second = self.parent_helper.config.get("dns_queries_per_second", 100)
        self.dns_rate_limiter = RateLimiter(self.dns_queries_per_second, "DNS")
        self._debug = self.parent_helper.config.get("dns_debug", False)
        self._dummy_modules = dict()
        self._dns_cache = self.parent_helper.CacheDict(max_size=100000)
        self._event_cache = self.parent_helper.CacheDict(max_size=10000)
        self._event_cache_locks = NamedLock()

        # copy the system's current resolvers to a text file for tool use
        self.system_resolvers = dns.resolver.Resolver().nameservers
        self.resolver_file = self.parent_helper.tempfile(self.system_resolvers, pipe=False)

        self.filter_bad_ptrs = self.parent_helper.config.get("dns_filter_ptrs", True)

    async def resolve(self, query, **kwargs):
        """
        "1.2.3.4" --> {
            "evilcorp.com",
        }
        "evilcorp.com" --> {
            "1.2.3.4",
            "dead::beef"
        }
        """
        results = set()
        r = await self.resolve_raw(query, **kwargs)
        if r:
            raw_results, errors = r
            for rdtype, answers in raw_results:
                for answer in answers:
                    for _, t in self.extract_targets(answer):
                        results.add(t)
        return results

    async def resolve_raw(self, query, **kwargs):
        # DNS over TCP is more reliable
        # But setting this breaks DNS resolution on Ubuntu because systemd-resolve doesn't support TCP
        # kwargs["tcp"] = True
        results = []
        errors = []
        query = str(query).strip()
        try:
            if is_ip(query):
                kwargs.pop("type", None)
                kwargs.pop("rdtype", None)
                results, errors = await self._resolve_ip(query, **kwargs)
                return [("PTR", results)], [("PTR", e) for e in errors]
            else:
                types = ["A", "AAAA"]
                kwargs.pop("rdtype", None)
                if "type" in kwargs:
                    t = kwargs.pop("type")
                    if isinstance(t, str):
                        if t.strip().lower() in ("any", "all", "*"):
                            types = self.all_rdtypes
                        else:
                            types = [t.strip().upper()]
                    elif any([isinstance(t, x) for x in (list, tuple)]):
                        types = [str(_).strip().upper() for _ in t]
                for t in types:
                    r, e = await self._resolve_hostname(query, rdtype=t, **kwargs)
                    if r:
                        results.append((t, r))
                    for error in e:
                        errors.append((t, error))
        except RuntimeError as e:
            log.debug(f"Error in resolve_raw({query}, kwargs={kwargs}): {e}")
            log.trace(traceback.format_exc())

        return (results, errors)

    async def _resolve_hostname(self, query, **kwargs):
        self.debug(f"Resolving {query} with kwargs={kwargs}")
        results = []
        errors = []
        rdtype = kwargs.get("rdtype", "A")

        # skip certain queries if requested
        if rdtype in self.dns_omit_queries:
            if any(h == query or query.endswith(f".{h}") for h in self.dns_omit_queries[rdtype]):
                self.debug(f"Skipping {rdtype}:{query} because it's omitted in the config")
                return results, errors

        parent = self.parent_helper.parent_domain(query)
        retries = kwargs.pop("retries", self.retries)
        cache_result = kwargs.pop("cache_result", False)
        tries_left = int(retries) + 1
        parent_hash = hash(f"{parent}:{rdtype}")
        dns_cache_hash = hash(f"{query}:{rdtype}")
        while tries_left > 0:
            try:
                try:
                    results = self._dns_cache[dns_cache_hash]
                except KeyError:
                    error_count = self._errors.get(parent_hash, 0)
                    if error_count >= self.abort_threshold:
                        log.verbose(
                            f'Aborting query "{query}" because failed {rdtype} queries for "{parent}" ({error_count:,}) exceeded abort threshold ({self.abort_threshold:,})'
                        )
                        return results, errors
                    async with self.dns_rate_limiter:
                        results = await self._catch(self.resolver.resolve, query, **kwargs)
                    if cache_result:
                        self._dns_cache[dns_cache_hash] = results
                    if parent_hash in self._errors:
                        self._errors[parent_hash] = 0
                break
            except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
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
                    log.verbose(err_msg)

        return results, errors

    async def _resolve_ip(self, query, **kwargs):
        self.debug(f"Reverse-resolving {query} with kwargs={kwargs}")
        retries = kwargs.pop("retries", 0)
        cache_result = kwargs.pop("cache_result", False)
        tries_left = int(retries) + 1
        results = []
        errors = []
        dns_cache_hash = hash(f"{query}:PTR")
        while tries_left > 0:
            try:
                try:
                    results = self._dns_cache[dns_cache_hash]
                except KeyError:
                    async with self.dns_rate_limiter:
                        results = await self._catch(self.resolver.resolve_address, query, **kwargs)
                    if cache_result:
                        self._dns_cache[dns_cache_hash] = results
                break
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout, dns.resolver.NoNameservers) as e:
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
        self.debug(f"Results for {query} with kwargs={kwargs}: {results}")
        return results, errors

    async def handle_wildcard_event(self, event, children):
        event_host = str(event.host)
        # wildcard checks
        if not is_ip(event.host):
            # check if this domain is using wildcard dns
            event_target = "target" in event.tags
            for hostname, wildcard_domain_rdtypes in (
                await self.is_wildcard_domain(event_host, log_info=event_target)
            ).items():
                if wildcard_domain_rdtypes:
                    event.add_tag("wildcard-domain")
                    for rdtype, ips in wildcard_domain_rdtypes.items():
                        event.add_tag(f"{rdtype.lower()}-wildcard-domain")
            # check if the dns name itself is a wildcard entry
            wildcard_rdtypes = await self.is_wildcard(event_host)
            for rdtype, (is_wildcard, wildcard_host) in wildcard_rdtypes.items():
                wildcard_tag = "error"
                if is_wildcard == True:
                    event.add_tag("wildcard")
                    wildcard_tag = "wildcard"
                event.add_tag(f"{rdtype.lower()}-{wildcard_tag}")

        # wildcard event modification (www.evilcorp.com --> _wildcard.evilcorp.com)
        if not is_ip(event.host) and wildcard_rdtypes and children:
            # these are the rdtypes that successfully resolve
            resolved_rdtypes = set([c.upper() for c in children])
            # these are the rdtypes that have wildcards
            wildcard_rdtypes_set = set(wildcard_rdtypes)
            # consider the event a full wildcard if all its records are wildcards
            event_is_wildcard = False
            if resolved_rdtypes:
                event_is_wildcard = all(r in wildcard_rdtypes_set for r in resolved_rdtypes)
            # if event_is_wildcard and event.type in ("DNS_NAME",) and not "_wildcard" in event.data.split("."):
            if event_is_wildcard:
                if event.type in ("DNS_NAME",) and not "_wildcard" in event.data.split("."):
                    wildcard_parent = self.parent_helper.parent_domain(event_host)
                    for rdtype, (_is_wildcard, _parent_domain) in wildcard_rdtypes.items():
                        if _is_wildcard:
                            wildcard_parent = _parent_domain
                            break
                    wildcard_data = f"_wildcard.{wildcard_parent}"
                    if wildcard_data != event.data:
                        log.debug(f'Wildcard detected, changing event.data "{event.data}" --> "{wildcard_data}"')
                        event.data = wildcard_data

    async def resolve_event(self, event, minimal=False):
        """
        Tag event with appropriate dns record types
        Optionally create child events from dns resolutions
        """
        log.debug(f"Resolving {event}")
        event_host = str(event.host)
        event_tags = set()
        dns_children = dict()
        event_whitelisted = False
        event_blacklisted = False

        if not event.host or event.type in ("IP_RANGE",):
            return event_tags, event_whitelisted, event_blacklisted, dns_children

        # lock to ensure resolution of the same host doesn't start while we're working here
        async with self._event_cache_locks.lock(event_host):
            # try to get data from cache
            _event_tags, _event_whitelisted, _event_blacklisted, _dns_children = self.event_cache_get(event_host)
            event_tags.update(_event_tags)
            # if we found it, return it
            if _event_whitelisted is not None:
                return event_tags, _event_whitelisted, _event_blacklisted, _dns_children

            # then resolve
            types = ()
            if self.parent_helper.is_ip(event.host):
                if not minimal:
                    types = ("PTR",)
            else:
                if event.type == "DNS_NAME" and not minimal:
                    types = self.all_rdtypes
                else:
                    types = ("A", "AAAA")

            if types:
                tasks = [asyncio.create_task(self.resolve_raw(event_host, type=t, cache_result=True)) for t in types]
                for task in asyncio.as_completed(tasks):
                    resolved_raw, errors = await task
                    for rdtype, e in errors:
                        if rdtype not in resolved_raw:
                            event_tags.add(f"{rdtype.lower()}-error")
                    for rdtype, records in resolved_raw:
                        rdtype = str(rdtype).upper()
                        if records:
                            event_tags.add("resolved")
                            event_tags.add(f"{rdtype.lower()}-record")

                        # whitelisting and blacklisting of IPs
                        for r in records:
                            for _, t in self.extract_targets(r):
                                if t:
                                    ip = self.parent_helper.make_ip_type(t)

                                    if rdtype in ("A", "AAAA", "CNAME"):
                                        with contextlib.suppress(ValidationError):
                                            if self.parent_helper.is_ip(ip):
                                                if self.parent_helper.scan.whitelisted(ip):
                                                    event_whitelisted = True
                                        with contextlib.suppress(ValidationError):
                                            if self.parent_helper.scan.blacklisted(ip):
                                                event_blacklisted = True

                                    if self.filter_bad_ptrs and rdtype in ("PTR") and self.parent_helper.is_ptr(t):
                                        self.debug(f"Filtering out bad PTR: {t}")
                                        continue

                                    try:
                                        dns_children[rdtype].add(ip)
                                    except KeyError:
                                        dns_children[rdtype] = {ip}

                # tag with cloud providers
                if not self.parent_helper.in_tests:
                    to_check = set()
                    if event.type == "IP_ADDRESS":
                        to_check.add(event.data)
                    for rdtype, ips in dns_children.items():
                        if rdtype in ("A", "AAAA"):
                            for ip in ips:
                                to_check.add(ip)
                    for ip in to_check:
                        provider, provider_type, subnet = cloudcheck(ip)
                        if provider:
                            event_tags.add(f"{provider_type}-{provider}")

                # if needed, mark as unresolved
                if not is_ip(event_host) and "resolved" not in event_tags:
                    event_tags.add("unresolved")
                # check for private IPs
                for rdtype, ips in dns_children.items():
                    for ip in ips:
                        try:
                            ip = ipaddress.ip_address(ip)
                            if ip.is_private:
                                event_tags.add("private-ip")
                        except ValueError:
                            continue

                self._event_cache[event_host] = (event_tags, event_whitelisted, event_blacklisted, dns_children)

        return event_tags, event_whitelisted, event_blacklisted, dns_children

    def event_cache_get(self, host):
        try:
            return self._event_cache[host]
        except KeyError:
            return set(), None, None, set()

    async def _resolve_batch_coro_wrapper(self, q, **kwargs):
        """
        Helps us correlate task results back to their original arguments
        """
        result = await self.resolve(q, **kwargs)
        return (q, result)

    async def resolve_batch(self, queries, **kwargs):
        """
        await resolve_batch(["www.evilcorp.com", "evilcorp.com"]) --> [
            ("www.evilcorp.com", {"1.1.1.1"}),
            ("evilcorp.com", {"2.2.2.2"})
        ]
        """

        for task in asyncio.as_completed(
            [asyncio.create_task(self._resolve_batch_coro_wrapper(q, **kwargs)) for q in queries]
        ):
            yield await task

    def extract_targets(self, record):
        """
        Extract whatever hostnames/IPs a DNS records points to
        """
        results = set()
        rdtype = str(record.rdtype.name).upper()
        if rdtype in ("A", "AAAA", "NS", "CNAME", "PTR"):
            results.add((rdtype, self._clean_dns_record(record)))
        elif rdtype == "SOA":
            results.add((rdtype, self._clean_dns_record(record.mname)))
        elif rdtype == "MX":
            results.add((rdtype, self._clean_dns_record(record.exchange)))
        elif rdtype == "SRV":
            results.add((rdtype, self._clean_dns_record(record.target)))
        elif rdtype == "TXT":
            for s in record.strings:
                s = self.parent_helper.smart_decode(s)
                for match in dns_name_regex.finditer(s):
                    start, end = match.span()
                    host = s[start:end]
                    results.add((rdtype, host))
        elif rdtype == "NSEC":
            results.add((rdtype, self._clean_dns_record(record.next)))
        else:
            log.warning(f'Unknown DNS record type "{rdtype}"')
        return results

    @staticmethod
    def _clean_dns_record(record):
        if not isinstance(record, str):
            record = str(record.to_text())
        return str(record).rstrip(".").lower()

    async def _catch(self, callback, *args, **kwargs):
        try:
            return await callback(*args, **kwargs)
        except dns.resolver.NoNameservers:
            raise
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            log.debug(f"DNS query with args={args}, kwargs={kwargs} timed out after {self.timeout} seconds")
            raise
        except dns.exception.DNSException as e:
            self.debug(f"{e} (args={args}, kwargs={kwargs})")
        except Exception as e:
            log.warning(f"Error in {callback.__qualname__}() with args={args}, kwargs={kwargs}: {e}")
            log.trace(traceback.format_exc())
        return []

    async def is_wildcard(self, query, ips=None, rdtype=None):
        """
        Use this method to check whether a *host* is a wildcard entry

        This can reliably tell the difference between a valid DNS record and a wildcard inside a wildcard domain.

        If you want to know whether a domain is using wildcard DNS, use is_wildcard_domain() instead.

        Returns a dictionary in the following format:
            {rdtype: (is_wildcard, wildcard_parent)}

            is_wildcard("www.github.io") --> {"A": (True, "github.io"), "AAAA": (True, "github.io")}

        Note that is_wildcard can be True, False, or None (indicating that wildcard detection was inconclusive)
        """
        result = {}

        if not is_dns_name(query):
            return {}

        # skip check if the query's parent domain is excluded in the config
        for d in self.wildcard_ignore:
            if self.parent_helper.host_in_host(query, d):
                log.debug(f"Skipping wildcard detection on {query} because it is excluded in the config")
                return {}

        if rdtype is None:
            rdtype = "ANY"

        query = self._clean_dns_record(query)
        # skip check if it's an IP
        if is_ip(query) or not "." in query:
            return {}
        # skip check if the query is a domain
        if is_domain(query):
            return {}

        parent = parent_domain(query)
        parents = list(domain_parents(query))

        wildcard_tasks = {t: [] for t in self.all_rdtypes}
        base_query_ips = dict()
        # if the caller hasn't already done the work of resolving the IPs
        if ips is None:
            # then resolve the query for all rdtypes
            for _rdtype in self.all_rdtypes:
                # resolve the base query
                wildcard_tasks[_rdtype].append(
                    asyncio.create_task(self.resolve_raw(query, type=_rdtype, cache_result=True))
                )

            for _rdtype, tasks in wildcard_tasks.items():
                for task in asyncio.as_completed(tasks):
                    raw_results, errors = await task
                    if errors and not raw_results:
                        self.debug(f"Failed to resolve {query} ({_rdtype}) during wildcard detection")
                        result[_rdtype] = (None, parent)
                        continue
                    for __rdtype, answers in raw_results:
                        base_query_ips[__rdtype] = set()
                        for answer in answers:
                            for _, t in self.extract_targets(answer):
                                base_query_ips[__rdtype].add(t)
        else:
            # otherwise, we can skip all that
            base_query_ips[rdtype] = set([self._clean_dns_record(ip) for ip in ips])
        if not base_query_ips:
            return result

        # once we've resolved the base query and have IP addresses to work with
        # we can compare the IPs to the ones we have on file for wildcards
        # for every rdtype
        for _rdtype in self.all_rdtypes:
            # get the IPs from above
            query_ips = base_query_ips.get("ANY", base_query_ips.get(_rdtype, set()))
            if not query_ips:
                continue
            # for every parent domain, starting with the longest
            for host in parents[::-1]:
                host_hash = hash(host)
                # make sure we've checked that domain for wildcards
                await self.is_wildcard_domain(host)
                if host_hash in self._wildcard_cache:
                    # then get its IPs from our wildcard cache
                    wildcard_rdtypes = self._wildcard_cache[host_hash]
                    # then check to see if our IPs match the wildcard ones
                    if _rdtype in wildcard_rdtypes:
                        wildcard_ips = wildcard_rdtypes[_rdtype]
                        # if our IPs match the wildcard ones, then ladies and gentlemen we have a wildcard
                        is_wildcard = any(r in wildcard_ips for r in query_ips)
                        if is_wildcard:
                            result[_rdtype] = (True, host)
                            break

        return result

    async def is_wildcard_domain(self, domain, log_info=False):
        """
        Check whether a domain is using wildcard DNS

        Returns a dictionary containing any DNS record types that are wildcards, and their associated IPs
            is_wildcard_domain("github.io") --> {"A": {"1.2.3.4",}, "AAAA": {"dead::beef",}}
        """
        wildcard_domain_results = {}
        domain = self._clean_dns_record(domain)

        if not is_dns_name(domain):
            return {}

        # skip check if the query's parent domain is excluded in the config
        for d in self.wildcard_ignore:
            if self.parent_helper.host_in_host(domain, d):
                log.debug(f"Skipping wildcard detection on {domain} because it is excluded in the config")
                return {}

        # make a list of its parents
        parents = list(domain_parents(domain, include_self=True))
        # and check each of them, beginning with the highest parent (i.e. the root domain)
        for i, host in enumerate(parents[::-1]):
            # have we checked this host before?
            host_hash = hash(host)
            async with self._wildcard_lock.lock(host_hash):
                # if we've seen this host before
                if host_hash in self._wildcard_cache:
                    wildcard_domain_results[host] = self._wildcard_cache[host_hash]
                    continue

                # determine if this is a wildcard domain
                wildcard_tasks = {t: [] for t in self.all_rdtypes}
                # resolve a bunch of random subdomains of the same parent
                for rdtype in self.all_rdtypes:
                    # continue if a wildcard was already found for this rdtype
                    # if rdtype in self._wildcard_cache[host_hash]:
                    #     continue
                    for _ in range(self.wildcard_tests):
                        rand_query = f"{rand_string(digits=False, length=10)}.{host}"
                        wildcard_tasks[rdtype].append(
                            asyncio.create_task(self.resolve(rand_query, type=rdtype, cache_result=False))
                        )

                # combine the random results
                is_wildcard = False
                wildcard_results = dict()
                for rdtype, tasks in wildcard_tasks.items():
                    for task in asyncio.as_completed(tasks):
                        results = await task
                        if results:
                            is_wildcard = True
                            if not rdtype in wildcard_results:
                                wildcard_results[rdtype] = set()
                            wildcard_results[rdtype].update(results)

                self._wildcard_cache.update({host_hash: wildcard_results})
                wildcard_domain_results.update({host: wildcard_results})
                if is_wildcard:
                    wildcard_rdtypes_str = ",".join(sorted([t.upper() for t, r in wildcard_results.items() if r]))
                    log_fn = log.verbose
                    if log_info:
                        log_fn = log.info
                    log_fn(f"Encountered domain with wildcard DNS ({wildcard_rdtypes_str}): {host}")

        return wildcard_domain_results

    def debug(self, *args, **kwargs):
        if self._debug:
            log.debug(*args, **kwargs)

    def _get_dummy_module(self, name):
        try:
            dummy_module = self._dummy_modules[name]
        except KeyError:
            dummy_module = self.parent_helper._make_dummy_module(name=name, _type="DNS")
            self._dummy_modules[name] = dummy_module
        return dummy_module
