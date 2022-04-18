import json
import logging
import dns.resolver
from threading import Lock

from .misc import is_ip, domain_parents, parent_domain, rand_string

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """
    For automatic wildcard detection, nameserver validation, etc.
    """

    def __init__(self, parent_helper):

        self.parent_helper = parent_helper
        self.wildcards = dict()
        self._cache = dict()
        self.resolver = dns.resolver.Resolver()
        self._resolver_list = None

        # since wildcard detection takes some time, these are to prevent multiple
        # modules from kicking off wildcard detection for the same domain at the same time
        # ensuring that subsequent calls to is_wildcard() will use the cached value
        self.__wildcard_lock = Lock()
        self._wildcard_locks = dict()

    def resolve(self, query, **kwargs):
        """
        Arguments:
            type: query type (A, AAAA, MX, etc.)
        """
        query = str(query).strip()
        if is_ip(query):
            return self._resolve_ip(query, **kwargs)
        else:
            results = set()
            types = ["A", "AAAA"]
            kwargs.pop("rdtype", None)
            if "type" in kwargs:
                types = [kwargs.pop("type")]
            for t in types:
                results.update(self._resolve_hostname(query, rdtype=t, **kwargs))
            return results

    def resolver_list(self, min_reliability=0.99):
        if self._resolver_list is None:
            nameservers = set()
            nameservers_url = "https://public-dns.info/nameserver/nameservers.json"
            nameservers_file = self.parent_helper.download(nameservers_url, cache_hrs=72)
            nameservers_json = []
            try:
                nameservers_json = json.loads(open(nameservers_file).read())
            except Exception as e:
                log.error(f"Failed to populate nameserver list from {nameservers_url}: {e}")
            for entry in nameservers_json:
                ip = str(entry.get("ip", "")).strip()
                try:
                    reliability = float(entry.get("reliability", 0))
                except ValueError:
                    continue
                if reliability >= min_reliability and is_ip(ip):
                    nameservers.add(ip)
            log.debug(f"Loaded {len(nameservers):,} nameservers from {nameservers_url}")
            self._resolver_list = self.verify_nameservers(nameservers)
        return self._resolver_list

    def verify_nameservers(self, nameservers, timeout=2):
        """Check each resolver to make sure it can actually resolve DNS names

        Args:
            nameservers (list): nameservers to verify
            timeout (int): timeout for dns query
        """
        log.debug(f"Verifying {len(nameservers):,} nameservers")
        futures = [self.parent_helper.submit_task(self.verify_nameserver, n) for n in nameservers]

        valid_nameservers = set()
        for future in self.parent_helper.as_completed(futures):
            nameserver, error = future.result()
            if error is None:
                log.debug(f'Nameserver "{nameserver}" is valid')
                valid_nameservers.add(nameserver)
            else:
                log.debug(str(error))

        return valid_nameservers

    def verify_nameserver(self, nameserver, timeout=2):
        """Validate a nameserver by making a sample query and a garbage query

        Args:
            nameserver (str): nameserver to verify
            timeout (int): timeout for dns query
        """
        log.debug(f'Verifying nameserver "{nameserver}"')
        error = None

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [nameserver]

        # first, make sure it can resolve google.com
        try:
            resolver.resolve("www.google.com", "A")
        except Exception:
            error = f"Nameserver {nameserver} failed to resolve basic query within {timeout} seconds"

        # then, make sure it isn't feeding us garbage data
        randhost = f"{rand_string(10)}.google.com"
        try:
            results = list(self.resolve(randhost, "A"))
            if results:
                error = f"Nameserver {nameserver} returned garbage data"
        except Exception:
            # Garbage query to nameserver failed successfully ;)
            pass

        return nameserver, error

    def _resolve_hostname(self, query, **kwargs):
        log.debug(f"Resolving {query} with kwargs={kwargs}")
        answers = set()
        try:
            for ip in list(dns.resolver.resolve(query, **kwargs)):
                answers.add(str(ip))
        except Exception as e:
            log.debug(f"Error resolving {query} with kwargs={kwargs}: {e}")
        return answers

    def _resolve_ip(self, query, **kwargs):
        log.debug(f"Reverse-resolving {query} with kwargs={kwargs}")
        answers = set()
        try:
            for host in list(dns.resolver.resolve_address(query, **kwargs)):
                answers.add(str(host).lower().rstrip("."))
        except Exception as e:
            log.debug(f"Error resolving {query} with kwargs={kwargs}: {e}")
        return answers

    def is_wildcard(self, query):
        parent = parent_domain(query)
        with self._wildcard_lock(parent):
            orig_results = self.resolve(query)
            parents = set(domain_parents(query))
            is_wildcard = False

            if parent in self._cache:
                return self._cache[parent]
            for parent in parents:
                if parent in self.wildcards:
                    return True

            futures = dict()
            for parent in parents:
                for _ in range(self.parent_helper.config.get("dns_wildcard_tests", 5)):
                    rand_query = f"{rand_string(length=10)}.{parent}"
                    future = self.parent_helper.submit_task(self.resolve, rand_query)
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
