import re
import json
import logging
import dns.resolver
import dns.exception
from threading import Lock
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor

from .regexes import dns_name_regex
from bbot.core.errors import ValidationError
from .threadpool import ThreadPoolWrapper, NamedLock
from .misc import is_ip, domain_parents, parent_domain, rand_string

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """
    For automatic wildcard detection, nameserver validation, etc.
    """

    def __init__(self, parent_helper):

        self.parent_helper = parent_helper
        self.resolver = dns.resolver.Resolver()
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
        kwargs["tcp"] = True
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
        parent_hash = hash(f"{parent}:{rdtype}")
        error_count = self._errors.get(parent_hash, 0)
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
        self.debug(f"Results for {query} with kwargs={kwargs}: {results}")
        return results, errors

    def _resolve_ip(self, query, **kwargs):
        self.debug(f"Reverse-resolving {query} with kwargs={kwargs}")
        results = []
        errors = []
        try:
            return list(self._catch(self.resolver.resolve_address, query, **kwargs)), errors
        except dns.resolver.NoNameservers as e:
            self.debug(f"{e} (query={query}, kwargs={kwargs})")
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
            errors.append(e)
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

                # wildcard check first
                if check_wildcard:
                    event_is_wildcard, wildcard_parent = self.is_wildcard(event_host)
                    if event_is_wildcard and event.type in ("DNS_NAME",):
                        event.data = wildcard_parent
                        return (event,)
                else:
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
            return set()
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
        log.verbose(f"Verifying {len(nameservers):,} nameservers")
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
        log.verbose(f"Verified {len(valid_nameservers):,}/{len(nameservers):,} nameservers")

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
        randhost = f"www-m.{rand_string(9)}.{rand_string(10)}.com"
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

    def is_wildcard(self, query):
        if is_ip(query) or not "." in query:
            return False, query
        for d in self.wildcard_ignore:
            if self.parent_helper.host_in_host(query, d):
                return False, query
        if "_wildcard" in query.split("."):
            return True, query
        hosts = list(domain_parents(query, include_self=True))[:-1]
        for host in hosts[::-1]:
            is_wildcard, parent = self._is_wildcard(host)
            if is_wildcard:
                return True, f"_wildcard.{parent}"
        return False, query

    def _is_wildcard(self, query):
        parent = parent_domain(query)
        parent_hash = hash(parent)

        # try to return from cache
        with suppress(KeyError):
            return self._wildcard_cache[parent_hash], parent

        with self._wildcard_lock.get_lock(parent):

            # resolve the base query
            orig_results = self.resolve(query)
            is_wildcard = False

            futures = []
            # resolve a bunch of random subdomains of the same parent
            for _ in range(self.wildcard_tests):
                rand_query = f"{rand_string(length=10)}.{parent}"
                future = self._thread_pool.submit_task(self._catch_keyboardinterrupt, self.resolve, rand_query)
                futures.append(future)

            # put all the IPs from the random subdomains in one bucket
            wildcard_ips = set()
            for future in self.parent_helper.as_completed(futures):
                ips = future.result()
                if ips:
                    wildcard_ips.update(ips)

            # if all of the original results are in the random bucket
            if orig_results and wildcard_ips and all([ip in wildcard_ips for ip in orig_results]):
                # then ladies and gentlemen we have a wildcard
                is_wildcard = True

            self._wildcard_cache.update({parent_hash: is_wildcard})
            if is_wildcard:
                log.verbose(f"Encountered domain with wildcard DNS: {parent}")
            return is_wildcard, parent

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
