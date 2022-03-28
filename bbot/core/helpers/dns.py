import logging
import dns.resolver

import concurrent.futures

from .misc import is_ip, domain_parents, rand_string

log = logging.getLogger("bbot.core.helpers.dns")


class DNSHelper:
    """
    For automatic wildcard detection
    """

    def __init__(self, config):

        self.config = config
        self.wildcards = dict()
        self.resolver = dns.resolver.Resolver()
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=25)

    def resolve(self, query, **kwargs):
        """
        Arguments:
            type: query type (A, AAAA, MX, etc.)
        """
        query = str(query).strip()
        if is_ip(query):
            return self._resolve_ip(query, **kwargs)
        else:
            kwargs["rdtype"] = kwargs.pop("type", "A")
            return self._resolve_hostname(query, **kwargs)

    def _resolve_hostname(self, query, **kwargs):
        answers = set()
        try:
            for ip in list(dns.resolver.resolve(query, **kwargs)):
                answers.add(str(ip))
        except Exception as e:
            log.debug(f"Error resolving {query} with kwargs={kwargs}: {e}")
        return answers

    def _resolve_ip(self, query, **kwargs):
        answers = set()
        try:
            for host in list(dns.resolver.resolve_address(query, **kwargs)):
                answers.add(str(host).lower())
        except Exception as e:
            log.debug(f"Error resolving {query} with kwargs={kwargs}: {e}")
        return answers

    def is_wildcard(self, query):
        orig_results = self.resolve(query)
        parents = set(domain_parents(query))

        for parent in parents:
            if parent in self.wildcards:
                return True

        futures = dict()
        for parent in parents:
            for _ in range(self.config.get("dns_wildcard_tests", 5)):
                rand_query = f"{rand_string(length=8)}.{parent}"
                futures[self._thread_pool.submit(self.resolve, rand_query)] = parent

        wildcard_ips = set()
        for future in concurrent.futures.as_completed(futures):
            parent = futures[future]
            ips = future.result()
            if ips:
                try:
                    self.wildcards[parent].update(ips)
                except KeyError:
                    self.wildcards[parent] = ips
                wildcard_ips.update(ips)

        if all([ip in wildcard_ips for ip in orig_results]):
            return True

        return False
