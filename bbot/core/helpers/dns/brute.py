import random
import asyncio
import logging

from blastdns import Client, ClientConfig, DNSError


class DNSBrute:
    """
    Helper for DNS brute-forcing.

    Uses its own blastdns client, separate from the one backing normal
    resolution: brute-forcing runs against a large public resolver list rather
    than the system resolvers, and needs its own concurrency and rate limits.

    Examples:
    >>> domain = "evilcorp.com"
    >>> subdomains = ["www", "mail"]
    >>> results = await self.helpers.dns.brute(domain, subdomains)
    """

    _nameservers_url = (
        "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
    )

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.log = logging.getLogger("bbot.helper.dns.brute")
        self.dns_config = self.parent_helper.config.get("dns", {})
        self.num_canaries = 100
        self.concurrency = self.dns_config.get("brute_concurrency", 1000)
        self.inflight_per_resolver = self.dns_config.get("brute_inflight_per_resolver", 2)
        self.rate_limit = self.dns_config.get("brute_rate_limit", 0)
        self.retries = self.dns_config.get("brute_retries", 20)
        self.timeout = self.dns_config.get("brute_timeout", 0.5)
        self.persistent_socket = self.dns_config.get("brute_persistent_socket", True)
        self.nameservers_url = self.dns_config.get("brute_nameservers", self._nameservers_url)
        self.devops_mutations = list(self.parent_helper.word_cloud.devops_mutations)
        self.digit_regex = self.parent_helper.re.compile(r"\d+")
        self._resolver_file = None
        self._client = None
        self._client_lock = None
        self._dnsbrute_lock = None

    async def __call__(self, *args, **kwargs):
        return await self.dnsbrute(*args, **kwargs)

    @property
    def dnsbrute_lock(self):
        if self._dnsbrute_lock is None:
            self._dnsbrute_lock = asyncio.Lock()
        return self._dnsbrute_lock

    @property
    def client_lock(self):
        if self._client_lock is None:
            self._client_lock = asyncio.Lock()
        return self._client_lock

    async def client(self):
        """The blastdns client used for brute-forcing, built on first use.

        Construction is deferred because the resolver list has to be downloaded
        first, and blastdns takes its resolvers at construction time.
        """
        async with self.client_lock:
            if self._client is None:
                resolver_file = await self.resolver_file()
                resolvers = list(self.parent_helper.read_file(resolver_file))
                self.log.verbose(f"Starting brute-force DNS client with {len(resolvers):,} resolvers")
                self._client = Client(
                    resolvers,
                    ClientConfig(
                        max_concurrency=self.concurrency,
                        max_inflight_per_resolver=self.inflight_per_resolver,
                        rate_limit=self.rate_limit or None,
                        # A public resolver list carries a lot of dead entries;
                        # drop them up front instead of paying for them all scan.
                        resolver_probe=True,
                        # Brute-force queries are unique by construction, so a
                        # cache would only consume memory.
                        cache_capacity=0,
                        request_timeout_ms=int(self.timeout * 1000),
                        max_retries=self.retries,
                        persistent_socket=self.persistent_socket,
                    ),
                )
            return self._client

    async def dnsbrute(self, domain, subdomains, type=None):
        subdomains = list(subdomains)

        if type is None:
            type = "A"
        type = str(type).strip().upper()

        wildcard_domains = await self.parent_helper.dns.is_wildcard_domain(domain, (type, "CNAME"))
        wildcard_rdtypes = set()
        for wildcard_domain, rdtypes in wildcard_domains.items():
            wildcard_rdtypes.update(rdtypes)
        if wildcard_domains:
            self.log.hugewarning(
                f"Aborting brute-force of {domain} because it's a wildcard domain ({','.join(sorted(wildcard_rdtypes))})"
            )
            return []

        canaries_list = list(self.gen_random_subdomains(self.num_canaries))
        canary_set = set(canaries_list)
        canaries_pre = canaries_list[: int(self.num_canaries / 2)]
        canaries_post = canaries_list[int(self.num_canaries / 2) :]
        # sandwich subdomains between canaries
        subdomains = canaries_pre + subdomains + canaries_post

        results = []
        canaries_triggered = []
        async for hostname in self._resolve_subdomains(domain, subdomains, rdtype=type):
            sub = hostname.split(domain)[0].rstrip(".")
            if sub in canary_set:
                canaries_triggered.append(sub)
            else:
                results.append(hostname)

        if len(canaries_triggered) > 5:
            self.log.info(
                f"Aborting brute-force of {domain} due to false positive: ({len(canaries_triggered):,} canaries triggered - {','.join(canaries_triggered)})"
            )
            return []

        # everything checks out
        return results

    async def _resolve_subdomains(self, domain, subdomains, rdtype):
        """Resolve each candidate under ``domain``, yielding the ones that exist.

        Uses ``resolve_batch_full`` rather than ``resolve_batch`` so failures stay
        visible: a query that ran out of retries is a silently missed subdomain,
        which is the one error brute-forcing must not hide.
        """
        client = await self.client()
        queries = self.gen_subdomains(subdomains, domain)
        suffix = f".{domain}"
        hosts_yielded = set()
        answered = 0
        empty = 0
        failed = 0

        # Runs are serialized by dnsbrute_lock, so a stats snapshot taken here
        # describes this run and no other.
        async with self.dnsbrute_lock:
            before = {s.resolver: s for s in client.stats()}
            async for host, result in client.resolve_batch_full(queries, rdtype):
                if isinstance(result, DNSError):
                    failed += 1
                    continue
                if not result.response.answers:
                    empty += 1
                    continue
                answered += 1

                # A CNAME can point anywhere; only names under the domain we
                # asked about are subdomains of it.
                hostname = host.strip(".").lower()
                if not hostname.endswith(suffix) or hostname in hosts_yielded:
                    continue
                hosts_yielded.add(hostname)
                yield hostname
            after = client.stats()

        self._log_delivery(domain, answered, empty, failed, before, after)

    def _log_delivery(self, domain, answered, empty, failed, before, after):
        """Report how much of the wordlist actually got an answer.

        A run that silently drops queries looks identical to one that found
        nothing, so unanswered queries are worth surfacing. When a meaningful
        share went unanswered, also report the resolver-side picture, since
        otherwise there's no way to tell rate-limiting apart from backoff.
        """
        total = answered + empty + failed
        if not total:
            return
        message = f"Brute-force of {domain}: {answered:,} resolved, {empty:,} no record, {failed:,} unanswered"
        if failed / total <= 0.05:
            self.log.verbose(message)
            return

        used = 0
        timeouts = 0
        paced = 0
        for stats in after:
            previous = before.get(stats.resolver)
            if stats.attempted - (previous.attempted if previous else 0):
                used += 1
            timeouts += stats.timeout - (previous.timeout if previous else 0)
            if stats.rate_qps is not None:
                paced += 1
        self.log.warning(
            f"{message} ({failed / total:.0%} unanswered, results may be incomplete). "
            f"{used:,} resolvers used, {paced:,} throttled by backoff, {timeouts:,} timeouts"
        )

    def gen_subdomains(self, prefixes, domain):
        for p in prefixes:
            if domain:
                p = f"{p}.{domain}"
            yield p

    async def resolver_file(self):
        if self._resolver_file is None:
            self._resolver_file_original = await self.parent_helper.wordlist(
                self.nameservers_url,
                cache_hrs=24 * 7,
            )
            nameservers = set(self.parent_helper.read_file(self._resolver_file_original))
            # exclude whatever the main DNS path is using, custom or system
            # this helps prevent rate-limiting which might cause BBOT's main dns queries to fail
            nameservers.difference_update(self.parent_helper.dns.resolvers)
            self._resolver_file = self.parent_helper.tempfile(nameservers, pipe=False)
        return self._resolver_file

    def gen_random_subdomains(self, n=50):
        delimiters = (".", "-")
        lengths = list(range(3, 8))
        for i in range(0, max(0, n - 5)):
            d = delimiters[i % len(delimiters)]
            l = lengths[i % len(lengths)]
            segments = [random.choice(self.devops_mutations) for _ in range(l)]
            segments.append(self.parent_helper.rand_string(length=8, digits=False))
            subdomain = d.join(segments)
            yield subdomain
        for _ in range(5):
            yield self.parent_helper.rand_string(length=8, digits=False)

    def has_excessive_digits(self, d):
        """
        Identifies dns names with excessive numbers, e.g.:
            - w1-2-3.evilcorp.com
            - ptr1234.evilcorp.com
        """
        is_ptr = self.parent_helper.is_ptr(d)
        digits = self.digit_regex.findall(d)
        excessive_digits = len(digits) > 2
        long_digits = any(len(d) > 3 for d in digits)
        return is_ptr or excessive_digits or long_digits
