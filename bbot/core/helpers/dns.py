import json
import logging
import dns.resolver
import dns.exception
from threading import Lock
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor

from .regexes import dns_name_regex
from ...modules.base import BaseModule
from ..threadpool import ThreadPoolWrapper
from bbot.core.errors import ValidationError
from .misc import is_ip, is_domain, domain_parents, parent_domain, rand_string

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """
    For automatic wildcard detection, nameserver validation, etc.
    """

    def __init__(self, parent_helper):

        self.parent_helper = parent_helper
        self.wildcards = dict()
        self.wildcard_tests = self.parent_helper.config.get("dns_wildcard_tests", 5)
        self._cache = dict()
        self.resolver = dns.resolver.Resolver()
        self.timeout = self.parent_helper.config.get("dns_timeout", 10)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        self._resolver_list = None

        # since wildcard detection takes some time, these are to prevent multiple
        # modules from kicking off wildcard detection for the same domain at the same time
        # ensuring that subsequent calls to is_wildcard() will use the cached value
        self.__wildcard_lock = Lock()
        self._wildcard_locks = dict()

        # we need our own threadpool because using the shared one can lead to deadlocks
        max_workers = self.parent_helper.config.get("max_threads", 100)
        executor = ThreadPoolExecutor(max_workers=max_workers)
        self._thread_pool = ThreadPoolWrapper(executor, max_workers=max_workers)

        self._debug = self.parent_helper.config.get("dns_debug", False)

        self._dummy_modules = dict()
        self._dummy_modules_lock = Lock()

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
        for rdtype, answers in self.resolve_raw(query, **kwargs):
            for answer in answers:
                for _, t in self.extract_targets(answer):
                    results.add(t)
        return results

    def resolve_raw(self, query, **kwargs):
        query = str(query).strip()
        if is_ip(query):
            kwargs.pop("type", None)
            kwargs.pop("rdtype", None)
            return [
                ("PTR", self._resolve_ip(query, **kwargs)),
            ]
        else:
            results = []
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
                r = self._resolve_hostname(query, rdtype=t, **kwargs)
                if r:
                    results.append((t, r))

            return results

    def resolve_event(self, event, check_wildcard=True):
        """
        Tag event with appropriate dns record types
        Optionally create child events from dns resolutions
        """
        children = []
        source_trail = []
        make_event = self.parent_helper.scan.make_event
        for rdtype, records in self.resolve_raw(event.data, type="any"):
            event.tags.add("resolved")
            rdtype = str(rdtype).upper()
            if rdtype in ("A", "AAAA"):
                for r in records:
                    for _, t in self.extract_targets(r):
                        with suppress(ValidationError):
                            if self.parent_helper.scan.target.in_scope(t):
                                if not source_trail:
                                    source_trail = event.make_in_scope()
                                break
            for r in records:
                for _, t in self.extract_targets(r):
                    event.tags.add(f"{rdtype.lower()}_record")
                    module = self._get_dummy_module(rdtype)
                    children.append(make_event(t, "DNS_NAME", module=module, source=event))
        if "resolved" not in event.tags:
            event.tags.add("unresolved")
        if check_wildcard and event.type == "DNS_NAME":
            if self.is_wildcard(event.data):
                event.tags.add("wildcard")
        return children, source_trail

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
    def resolver_file(self):
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
            resolver.resolve("www.example.com", "A")
        except Exception:
            error = f"Nameserver {nameserver} failed to resolve basic query within {timeout} seconds"

        # then, make sure it isn't feeding us garbage data
        if error is None:
            randhost = f"{rand_string(9)}.{rand_string(10)}.com"
            try:
                resolver.resolve(randhost, "A")
                error = f"Nameserver {nameserver} returned garbage data"
            except dns.exception.DNSException:
                pass
                # Garbage query to nameserver failed successfully ;)

        return nameserver, error

    def _resolve_hostname(self, query, **kwargs):
        self.debug(f"Resolving {query} with kwargs={kwargs}")
        return list(self._catch(self.resolver.resolve, query, **kwargs))

    def _resolve_ip(self, query, **kwargs):
        self.debug(f"Reverse-resolving {query} with kwargs={kwargs}")
        return list(self._catch(self.resolver.resolve_address, query, **kwargs))

    def _catch(self, callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except dns.exception.Timeout:
            log.debug(f"DNS query with args={args}, kwargs={kwargs} timed out after {self.timeout} seconds")
        except dns.exception.DNSException as e:
            self.debug(f"{e} (args={args}, kwargs={kwargs})")
        except Exception:
            log.debug(f"Error in {callback.__name__} with args={args}, kwargs={kwargs}")
        return list()

    def is_wildcard(self, query):
        if is_domain(query):
            return False
        parent = parent_domain(query)

        if parent in self._cache:
            return self._cache[parent]

        with self._wildcard_lock(parent):
            orig_results = self.resolve(query)
            parents = set(domain_parents(query))
            is_wildcard = False

            for p in parents:
                if p in self.wildcards:
                    return True

            futures = dict()
            for parent in parents:
                for _ in range(self.wildcard_tests):
                    rand_query = f"{rand_string(length=10)}.{parent}"
                    future = self._thread_pool.submit_task(self._catch_keyboardinterrupt, self.resolve, rand_query)
                    futures[future] = parent

            wildcard_ips = set()
            for future in self.parent_helper.as_completed(futures):
                parent = futures[future]
                ips = future.result()
                if ips:
                    try:
                        self.wildcards[parent].update(ips)
                    except KeyError:
                        self.wildcards[parent] = ips
                    wildcard_ips.update(ips)

            if orig_results and wildcard_ips and all([ip in wildcard_ips for ip in orig_results]):
                is_wildcard = True

            self._cache.update({parent: is_wildcard})
        return is_wildcard

    def _wildcard_lock(self, domain):
        with self.__wildcard_lock:
            try:
                return self._wildcard_locks[domain]
            except KeyError:
                lock = Lock()
                self._wildcard_locks[domain] = lock
                return lock

    def _catch_keyboardinterrupt(self, callback, *args, **kwargs):
        try:
            return callback(*args, **kwargs)
        except Exception as e:
            import traceback

            log.error(f"Error in {callback.__name__()}: {e}")
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
                dummy_module = DNSDummyModule(name=name, scan=self.parent_helper.scan)
                self._dummy_modules[name] = dummy_module
        return dummy_module


class DNSDummyModule(BaseModule):
    _type = "DNS"

    def __init__(self, *args, **kwargs):
        self._name = kwargs.pop("name")
        super().__init__(*args, **kwargs)
