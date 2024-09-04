import json
import random
import asyncio
import logging
import subprocess


class DNSBrute:
    """
    Helper for DNS brute-forcing.

    Examples:
    >>> domain = "evilcorp.com"
    >>> subdomains = ["www", "mail"]
    >>> results = await self.helpers.dns.brute(self, domain, subdomains)
    """

    _nameservers_url = (
        "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
    )

    def __init__(self, parent_helper):
        self.parent_helper = parent_helper
        self.log = logging.getLogger("bbot.helper.dns.brute")
        self.dns_config = self.parent_helper.config.get("dns", {})
        self.num_canaries = 100
        self.max_resolvers = self.dns_config.get("brute_threads", 1000)
        self.nameservers_url = self.dns_config.get("brute_nameservers", self._nameservers_url)
        self.devops_mutations = list(self.parent_helper.word_cloud.devops_mutations)
        self.digit_regex = self.parent_helper.re.compile(r"\d+")
        self._resolver_file = None
        self._dnsbrute_lock = asyncio.Lock()

    async def __call__(self, *args, **kwargs):
        return await self.dnsbrute(*args, **kwargs)

    async def dnsbrute(self, module, domain, subdomains, type=None):
        subdomains = list(subdomains)

        if type is None:
            type = "A"
        type = str(type).strip().upper()

        wildcard_rdtypes = await self.parent_helper.dns.is_wildcard_domain(domain, (type, "CNAME"))
        if wildcard_rdtypes:
            self.log.hugewarning(
                f"Aborting massdns on {domain} because it's a wildcard domain ({','.join(wildcard_rdtypes)})"
            )
            return []

        canaries = self.gen_random_subdomains(self.num_canaries)
        canaries_list = list(canaries)
        canaries_pre = canaries_list[: int(self.num_canaries / 2)]
        canaries_post = canaries_list[int(self.num_canaries / 2) :]
        # sandwich subdomains between canaries
        subdomains = canaries_pre + subdomains + canaries_post

        results = []
        canaries_triggered = []
        async for hostname, ip, rdtype in self._massdns(module, domain, subdomains, rdtype=type):
            sub = hostname.split(domain)[0]
            if sub in canaries:
                canaries_triggered.append(sub)
            else:
                results.append(hostname)

        if len(canaries_triggered) > 5:
            self.log.info(
                f"Aborting massdns on {domain} due to false positive: ({len(canaries_triggered):,} canaries triggered - {','.join(canaries_triggered)})"
            )
            return []

        # everything checks out
        return results

    async def _massdns(self, module, domain, subdomains, rdtype):
        """
        {
            "name": "www.blacklanternsecurity.com.",
            "type": "A",
            "class": "IN",
            "status": "NOERROR",
            "data": {
            "answers": [
                {
                "ttl": 3600,
                "type": "CNAME",
                "class": "IN",
                "name": "www.blacklanternsecurity.com.",
                "data": "blacklanternsecurity.github.io."
                },
                {
                "ttl": 3600,
                "type": "A",
                "class": "IN",
                "name": "blacklanternsecurity.github.io.",
                "data": "185.199.108.153"
                }
            ]
            },
            "resolver": "168.215.165.186:53"
        }
        """
        resolver_file = await self.resolver_file()
        command = (
            "massdns",
            "-r",
            resolver_file,
            "-s",
            self.max_resolvers,
            "-t",
            rdtype,
            "-o",
            "J",
            "-q",
        )
        subdomains = self.gen_subdomains(subdomains, domain)
        hosts_yielded = set()
        async with self._dnsbrute_lock:
            async for line in module.run_process_live(*command, stderr=subprocess.DEVNULL, input=subdomains):
                try:
                    j = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.log.debug(f"Failed to decode line: {line}")
                    continue
                answers = j.get("data", {}).get("answers", [])
                if type(answers) == list and len(answers) > 0:
                    answer = answers[0]
                    hostname = answer.get("name", "").strip(".").lower()
                    if hostname.endswith(f".{domain}"):
                        data = answer.get("data", "")
                        rdtype = answer.get("type", "").upper()
                        if data and rdtype:
                            hostname_hash = hash(hostname)
                            if hostname_hash not in hosts_yielded:
                                hosts_yielded.add(hostname_hash)
                                yield hostname, data, rdtype

    async def gen_subdomains(self, prefixes, domain):
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
            nameservers.difference_update(self.parent_helper.dns.system_resolvers)
            # exclude system nameservers from brute-force
            # this helps prevent rate-limiting which might cause BBOT's main dns queries to fail
            self._resolver_file = self.parent_helper.tempfile(nameservers, pipe=False)
        return self._resolver_file

    def gen_random_subdomains(self, n=50):
        delimiters = (".", "-")
        lengths = list(range(3, 8))
        for i in range(0, max(0, n - 5)):
            d = delimiters[i % len(delimiters)]
            l = lengths[i % len(lengths)]
            segments = list(random.choice(self.devops_mutations) for _ in range(l))
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
