import re
import json
import logging
import dns.resolver
import dns.exception
from threading import Lock
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor

from .regexes import dns_name_regex
from .threadpool import ThreadPoolWrapper, NamedLock
from bbot.core.errors import ValidationError, DNSError
from .misc import is_ip, is_domain, domain_parents, parent_domain, rand_string

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """
    For automatic wildcard detection, nameserver validation, etc.
    """

    def __init__(self, parent_helper):

        self.parent_helper = parent_helper
        try:
            self.resolver = dns.resolver.Resolver()
        except Exception as e:
            raise DNSError(f"Failed to create BBOT DNS resolver: {e}")
        self.timeout = self.parent_helper.config.get("dns_timeout", 10)
        self.abort_threshold = self.parent_helper.config.get("dns_abort_threshold", 5)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        self._resolver_list = None

        self.wildcard_ignore = self.parent_helper.config.get("dns_wildcard_ignore", None)
        if not self.wildcard_ignore:
            self.wildcard_ignore = []
        self.wildcard_ignore = tuple([str(d).strip().lower() for d in self.wildcard_ignore])
        self.wildcard_tests = self.parent_helper.config.get("dns_wildcard_tests", 5)
        self._wildcard_cache = dict()
        # since wildcard detection takes some time, This is to prevent multiple
        # modules from kicking off wildcard detection for the same domain at the same time
        self._wildcard_lock = NamedLock()

        self._errors = dict()
        self._error_lock = Lock()

        self.fallback_nameservers_file = self.parent_helper.wordlist_dir / "nameservers.txt"

        # we need our own threadpool because using the shared one can lead to deadlocks
        max_workers = self.parent_helper.config.get("max_dns_threads", 100)
        executor = ThreadPoolExecutor(max_workers=max_workers)
        self._thread_pool = ThreadPoolWrapper(executor, max_workers=max_workers)

        self._debug = self.parent_helper.config.get("dns_debug", False)

        self._dummy_modules = dict()
        self._dummy_modules_lock = Lock()

        self._cache = self.parent_helper.CacheDict(max_size=10000)
        self._cache_lock = Lock()
        self._cache_locks = NamedLock()

        # copy the system's current resolvers to a text file for tool use
        resolvers = dns.resolver.Resolver().nameservers
        self.resolver_file = self.parent_helper.tempfile(resolvers, pipe=False)

        self.bad_ptr_regex = re.compile(r"(?:[0-9]{1,3}[-_\.]){3}[0-9]{1,3}")
        self.filter_bad_ptrs = self.parent_helper.config.get("dns_filter_ptrs", True)

    def resolve(self, query, **kwargs):
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
        raw_results, errors = self.resolve_raw(query, **kwargs)
        for (rdtype, answers) in raw_results:
            for answer in answers:
                for _, t in self.extract_targets(answer):
                    results.add(t)
        return results

    def resolve_raw(self, query, **kwargs):
        # DNS over TCP is more reliable
        # But setting this breaks DNS resolution on Ubuntu because systemd-resolve doesn't support TCP
        # kwargs["tcp"] = True
        if self.parent_helper.scan.stopping:
            return [], []
        query = str(query).strip()
        if is_ip(query):
            kwargs.pop("type", None)
            kwargs.pop("rdtype", None)
            results, errors = self._resolve_ip(query, **kwargs)
            return [("PTR", results)], [("PTR", e) for e in errors]
        else:
            results = []
            errors = []
            types = ["A", "AAAA"]
            kwargs.pop("rdtype", None)
            if "type" in kwargs:
                t = kwargs.pop("type")
                if isinstance(t, str):
                    if t.strip().lower() in ("any", "all", "*"):
                        types = ["A", "AAAA", "SRV", "MX", "NS", "SOA", "CNAME", "TXT"]
                    else:
                        types = [t.strip().upper()]
                elif any([isinstance(t, x) for x in (list, tuple)]):
                    types = [str(_).strip().upper() for _ in t]
            for t in types:
                if getattr(self.parent_helper.scan, "stopping", False) == True:
                    break
                r, e = self._resolve_hostname(query, rdtype=t, **kwargs)
                if r:
                    results.append((t, r))
                for error in e:
                    errors.append((t, error))

            return (results, errors)

    def _resolve_hostname(self, query, **kwargs):
        self.debug(f"Resolving {query} with kwargs={kwargs}")
        results = []
        errors = []
        parent = self.parent_helper.parent_domain(query)
        rdtype = kwargs.get("rdtype", "A")
        retries = kwargs.pop("retries", 0)
        tries_left = int(retries) + 1
        parent_hash = hash(f"{parent}:{rdtype}")
        error_count = self._errors.get(parent_hash, 0)
        while tries_left > 0:
            if error_count >= self.abort_threshold:
                log.verbose(
                    f'Aborting query "{query}" because failed {rdtype} queries for "{parent}" ({error_count:,}) exceeded abort threshold ({self.abort_threshold:,})'
                )
                return results, errors
            try:
                results = list(self._catch(self.resolver.resolve, query, **kwargs))
                with self._error_lock:
                    if parent_hash in self._errors:
                        self._errors[parent_hash] = 0
                break
            except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
                with self._error_lock:
                    try:
                        self._errors[parent_hash] += 1
                    except KeyError:
                        self._errors[parent_hash] = 1
                    log.verbose(
                        f'DNS error or timeout for {rdtype} query "{query}" ({self._errors[parent_hash]:,} so far): {e}'
                    )
                    errors.append(e)
                # don't retry if we get a SERVFAIL
                if isinstance(e, dns.resolver.NoNameservers):
                    break
                tries_left -= 1
                if tries_left > 0:
                    retry_num = (retries + 1) - tries_left
                    self.debug(f"Retry (#{retry_num}) resolving {query} with kwargs={kwargs}")

        self.debug(f"Results for {query} with kwargs={kwargs}: {results}")
        return results, errors

    def _resolve_ip(self, query, **kwargs):
        self.debug(f"Reverse-resolving {query} with kwargs={kwargs}")
        retries = kwargs.pop("retries", 0)
        tries_left = int(retries) + 1
        results = []
        errors = []
        while tries_left > 0:
            try:
                return list(self._catch(self.resolver.resolve_address, query, **kwargs)), errors
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

    def resolve_event(self, event):
        result = self._resolve_event(event)
        # if it's a wildcard, go again with _wildcard.{domain}
        if len(result) == 1:
            event = result[0]
            return self._resolve_event(event, check_wildcard=False)
        # else we're good
        else:
            return result

    def _resolve_event(self, event, check_wildcard=True):
        """
        Tag event with appropriate dns record types
        Optionally create child events from dns resolutions
        """
        event_tags = set()
        try:
            if not event.host or event.type in ("IP_RANGE",):
                return [], set(), False, False
            children = []
            event_host = str(event.host)
            # lock to ensure resolution of the same host doesn't start while we're working here
            with self._cache_locks.get_lock(event_host):

                event_whitelisted = False
                event_blacklisted = False

                host_is_domain = is_domain(event_host)

                # wildcard check first
                if check_wildcard:
                    event_is_wildcard, wildcard_parent = self.is_wildcard(event_host)
                    if event_is_wildcard and event.type in ("DNS_NAME",):
                        event.data = f"_wildcard.{wildcard_parent}"
                        return (event,)
                    elif event_is_wildcard is None:
                        event_tags.add("dns-error")
                elif not host_is_domain:
                    event_tags.add("wildcard")

                # try to get data from cache
                _event_tags, _event_whitelisted, _event_blacklisted = self.cache_get(event_host)
                event_tags.update(_event_tags)
                # if we found it, return it
                if _event_whitelisted is not None:
                    return children, event_tags, _event_whitelisted, _event_blacklisted

                # then resolve
                resolved_raw, errors = self.resolve_raw(event_host, type="any")
                if errors:
                    event_tags.add("dns-error")
                for rdtype, records in resolved_raw:
                    event_tags.add("resolved")
                    event_tags.add(f"{rdtype.lower()}_record")
                    rdtype = str(rdtype).upper()
                    # whitelisting and blacklist of IPs
                    if rdtype in ("A", "AAAA"):
                        for r in records:
                            for _, t in self.extract_targets(r):
                                with suppress(ValidationError):
                                    if self.parent_helper.scan.whitelisted(t):
                                        event_whitelisted = True
                                with suppress(ValidationError):
                                    if self.parent_helper.scan.blacklisted(t):
                                        event_blacklisted = True
                    for r in records:
                        for _, t in self.extract_targets(r):
                            if t:
                                if self.filter_bad_ptrs and rdtype in ("PTR") and self.bad_ptr_regex.search(t):
                                    self.debug(f"Filtering out bad PTR: {t}")
                                    continue
                                children.append((t, rdtype))
                if "resolved" not in event_tags:
                    event_tags.add("unresolved")
                self._cache[event_host] = (event_tags, event_whitelisted, event_blacklisted)
            return children, event_tags, event_whitelisted, event_blacklisted
        finally:
            event._resolved.set()

    def cache_get(self, host):
        try:
            return self._cache[host]
        except KeyError:
            return set(), None, None

    def resolve_batch(self, queries, **kwargs):
        """
        resolve_batch("www.evilcorp.com", "evilcorp.com") --> [
            ("www.evilcorp.com", {"1.1.1.1"}),
            ("evilcorp.com", {"2.2.2.2"})
        ]
        """
        futures = dict()
        for query in queries:
            future = self._thread_pool.submit_task(self._catch_keyboardinterrupt, self.resolve, query, **kwargs)
            futures[future] = query
        for future in self.parent_helper.as_completed(futures):
            query = futures[future]
            yield (query, future.result())

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
        else:
            log.warning(f'Unknown DNS record type "{rdtype}"')
        return results

    @staticmethod
    def _clean_dns_record(record):
        return str(record.to_text()).lower().rstrip(".")

    def get_valid_resolvers(self, min_reliability=0.99):
        nameservers = set()
        nameservers_url = "https://public-dns.info/nameserver/nameservers.json"
        nameservers_file = self.parent_helper.download(nameservers_url, cache_hrs=72)
        if nameservers_file is None:
            log.warning(f"Failed to download nameservers from {nameservers_url}")
        else:
            nameservers_json = []
            try:
                nameservers_json = json.loads(open(nameservers_file).read())
            except Exception as e:
                log.warning(f"Failed to load nameserver list from {nameservers_file}: {e}")
                nameservers_file.unlink()
            for entry in nameservers_json:
                try:
                    ip = str(entry.get("ip", "")).strip()
                except Exception:
                    continue
                try:
                    reliability = float(entry.get("reliability", 0))
                except ValueError:
                    continue
                if reliability >= min_reliability and is_ip(ip, version=4):
                    nameservers.add(ip)
            log.verbose(f"Loaded {len(nameservers):,} nameservers from {nameservers_url}")
        if not nameservers:
            log.info(f"Loading fallback nameservers from {self.fallback_nameservers_file}")
            lines = self.parent_helper.read_file(self.fallback_nameservers_file)
            nameservers = set([l for l in lines if not l.startswith("#")])
        resolver_list = self.verify_nameservers(nameservers)
        return resolver_list

    @property
    def resolvers(self):
        """
        Returns set() of valid DNS servers from public-dns.info
        """
        if self._resolver_list is None:
            file_content = self.parent_helper.cache_get("resolver_list")
            if file_content is not None:
                self._resolver_list = set([l for l in file_content.splitlines() if l])
            if not self._resolver_list:
                log.info(f"Fetching and validating public DNS servers, this may take a few minutes")
                resolvers = self.get_valid_resolvers()
                if resolvers:
                    self._resolver_list = resolvers
                    self.parent_helper.cache_put("resolver_list", "\n".join(self._resolver_list))
                else:
                    return set()
        return self._resolver_list

    @property
    def mass_resolver_file(self):
        self.resolvers
        return self.parent_helper.cache_filename("resolver_list")

    def verify_nameservers(self, nameservers, timeout=2):
        """Check each resolver to make sure it can actually resolve DNS names

        Args:
            nameservers (list): nameservers to verify
            timeout (int): timeout for dns query
        """
        log.info(f"Verifying {len(nameservers):,} nameservers")
        futures = [
            self._thread_pool.submit_task(self._catch_keyboardinterrupt, self.verify_nameserver, n)
            for n in nameservers
        ]

        valid_nameservers = set()
        for future in self.parent_helper.as_completed(futures):
            nameserver, error = future.result()
            if error is None:
                self.debug(f'Nameserver "{nameserver}" is valid')
                valid_nameservers.add(nameserver)
            else:
                self.debug(str(error))
        log.info(f"Successfully verified {len(valid_nameservers):,}/{len(nameservers):,} nameservers")

        return valid_nameservers

    def verify_nameserver(self, nameserver, timeout=2):
        """Validate a nameserver by making a sample query and a garbage query

        Args:
            nameserver (str): nameserver to verify
            timeout (int): timeout for dns query
        """
        self.debug(f'Verifying nameserver "{nameserver}"')
        error = None

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [nameserver]

        # first, make sure it can resolve a valid hostname
        try:
            a_results = [str(r) for r in list(resolver.resolve("dns.google", "A"))]
            aaaa_results = [str(r) for r in list(resolver.resolve("dns.google", "AAAA"))]
            if not ("2001:4860:4860::8888" in aaaa_results and "8.8.8.8" in a_results):
                error = f"Nameserver {nameserver} failed to resolve basic query"
        except Exception:
            error = f"Nameserver {nameserver} failed to resolve basic query within {timeout} seconds"

        # then, make sure it isn't feeding us garbage data
        randhost = f"www-m.{rand_string(9, digits=False)}.{rand_string(10, digits=False)}.com"
        if error is None:
            try:
                a_results = list(resolver.resolve(randhost, "A"))
                error = f"Nameserver {nameserver} returned garbage data"
            except dns.exception.DNSException:
                pass
                # Garbage query to nameserver failed successfully ;)
        if error is None:
            try:
                a_results = list(resolver.resolve(randhost, "AAAA"))
                error = f"Nameserver {nameserver} returned garbage data"
            except dns.exception.DNSException:
                pass
                # Garbage query to nameserver failed successfully ;)

        return nameserver, error

    def _catch(self, callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except dns.resolver.NoNameservers:
            raise
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            log.debug(f"DNS query with args={args}, kwargs={kwargs} timed out after {self.timeout} seconds")
            raise
        except dns.exception.DNSException as e:
            self.debug(f"{e} (args={args}, kwargs={kwargs})")
        except Exception:
            log.warning(f"Error in {callback.__qualname__}() with args={args}, kwargs={kwargs}")
        return list()

    def is_wildcard(self, query, ips=None, retries=5):
        """
        Use this method to check whether a *host* is a wildcard entry

        This works (it will return False) for valid A-records in a wildcard domain.

        If you want to know whether a domain is using wildcard DNS, use is_wildcard_domain() instead.

        Note that this method returns a tuple: (is_wildcard, parent_domain) where parent_domain is
        the highest level where wildcard checking occurred for that host.

        e.g. if you are checking www.external.evilcorp.com and evilcorp.com is a wildcard domain,
        this method will return (True, "evilcorp.com").
        """
        query = str(query).lower().rstrip(".")
        # skip check if it's an IP
        if is_ip(query) or not "." in query:
            return False, query
        # skip check if the query is a domain
        if is_domain(query):
            return False, query
        # skip check if the query's parent domain is excluded in the config
        for d in self.wildcard_ignore:
            if self.parent_helper.host_in_host(query, d):
                return False, query
        # if it's already been marked as a wildcard, return True
        if "_wildcard" in query.split("."):
            return True, query

        # populate wildcard cache
        parent = parent_domain(query)
        parents = list(domain_parents(query))
        # resolve the base query
        if ips is None:
            query_ips = self.resolve(query, type=("A", "AAAA"), retries=retries)
        else:
            query_ips = set(ips)
        if not query_ips:
            # return None (inconclusive) if main query fails to resolve
            return None, parent

        for host in parents[::-1]:
            host_hash = hash(host)
            if host_hash not in self._wildcard_cache:
                self.is_wildcard_domain(host)
            # if we've seen this domain before
            if host_hash in self._wildcard_cache:
                wildcard_ips = self._wildcard_cache[host_hash]
                # otherwise check to see if the dns name matches the wildcard IPs
                if wildcard_ips:
                    # if the results are the same as the wildcard IPs, then ladies and gentlemen we have a wildcard
                    is_wildcard = all(r in wildcard_ips for r in query_ips)
                    if is_wildcard:
                        return True, host
            else:
                log.warning(
                    f"Wildcard DNS detection failed for {parent}. Recommend increasing dns_wildcard_tests in config."
                )
                return None, host
        return False, parent

    def is_wildcard_domain(self, domain, retries=5):
        """
        Check whether a domain is using wildcard DNS
        """
        domain = str(domain).lower().rstrip(".")
        # make a list of its parents
        parents = list(domain_parents(domain, include_self=True))
        # and check each of them
        for host in parents[::-1]:
            host_hash = hash(host)
            with self._wildcard_lock.get_lock(host_hash):
                if host_hash in self._wildcard_cache:
                    if self._wildcard_cache[host_hash]:
                        return True
                    else:
                        continue
                # determine if this is a wildcard domain
                futures = []
                # resolve a bunch of random subdomains of the same parent
                for _ in range(self.wildcard_tests):
                    rand_query = f"{rand_string(digits=False, length=10)}.{host}"
                    future = self._thread_pool.submit_task(
                        self._catch_keyboardinterrupt, self.resolve, rand_query, retries=retries
                    )
                    futures.append(future)

                # put all the IPs from the random subdomains in one bucket
                wildcard_ips = set()
                for future in self.parent_helper.as_completed(futures):
                    ips = future.result()
                    if ips:
                        wildcard_ips.update(ips)

                self._wildcard_cache.update({host_hash: wildcard_ips})
                if wildcard_ips:
                    log.info(f"Encountered domain with wildcard DNS: {host}")
                    return True
        return False

    def _catch_keyboardinterrupt(self, callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except Exception as e:
            import traceback

            log.error(f"Error in {callback.__qualname__}(): {e}")
            log.debug(traceback.format_exc())
        except KeyboardInterrupt:
            if self.parent_helper.scan:
                self.parent_helper.scan.stop()

    def debug(self, *args, **kwargs):
        if self._debug:
            log.debug(*args, **kwargs)

    def _get_dummy_module(self, name):
        with self._dummy_modules_lock:
            try:
                dummy_module = self._dummy_modules[name]
            except KeyError:
                dummy_module = self.parent_helper._make_dummy_module(name=name, _type="DNS")
                self._dummy_modules[name] = dummy_module
        return dummy_module
