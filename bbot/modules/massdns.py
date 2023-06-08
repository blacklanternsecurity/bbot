import re
import json
import random
import subprocess

from .crobat import crobat


class massdns(crobat):
    flags = ["subdomain-enum", "passive", "slow", "aggressive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Brute-force subdomains with massdns (highly effective)"}
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "max_resolvers": 1000,
        "max_mutations": 500,
    }
    options_desc = {
        "wordlist": "Subdomain wordlist URL",
        "max_resolvers": "Number of concurrent massdns resolvers",
        "max_mutations": "Max number of smart mutations per subdomain",
    }
    subdomain_file = None
    deps_ansible = [
        {
            "name": "install dev tools",
            "package": {"name": ["gcc", "git", "make"], "state": "present"},
            "become": True,
            "ignore_errors": True,
        },
        {
            "name": "Download massdns source code",
            "git": {
                "repo": "https://github.com/blechschmidt/massdns.git",
                "dest": "#{BBOT_TEMP}/massdns",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build massdns (Linux)",
            "command": {"chdir": "#{BBOT_TEMP}/massdns", "cmd": "make", "creates": "#{BBOT_TEMP}/massdns/bin/massdns"},
            "when": "ansible_facts['system'] == 'Linux'",
        },
        {
            "name": "Build massdns (non-Linux)",
            "command": {
                "chdir": "#{BBOT_TEMP}/massdns",
                "cmd": "make nolinux",
                "creates": "#{BBOT_TEMP}/massdns/bin/massdns",
            },
            "when": "ansible_facts['system'] != 'Linux'",
        },
        {
            "name": "Install massdns",
            "copy": {"src": "#{BBOT_TEMP}/massdns/bin/massdns", "dest": "#{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]
    reject_wildcards = "strict"
    _qsize = 100

    digit_regex = re.compile(r"\d+")

    async def setup(self):
        self.found = dict()
        self.mutations_tried = set()
        self.source_events = dict()
        self.subdomain_file = await self.helpers.wordlist(self.config.get("wordlist"))
        self.max_resolvers = self.config.get("max_resolvers", 1000)
        self.max_mutations = self.config.get("max_mutations", 500)
        nameservers_url = (
            "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
        )
        self.resolver_file = await self.helpers.wordlist(
            nameservers_url,
            cache_hrs=24 * 7,
        )
        self.devops_mutations = list(self.helpers.word_cloud.devops_mutations)
        return await super().setup()

    async def filter_event(self, event):
        query = self.make_query(event)
        eligible, reason = await self.eligible_for_enumeration(event)
        if eligible:
            self.add_found(event)
        # reject if already processed
        if self.already_processed(query):
            return False, f'Query "{query}" was already processed'
        if eligible:
            self.processed.add(hash(query))
            return True, reason
        return False, reason

    async def handle_event(self, event):
        query = self.make_query(event)
        h = hash(query)
        if not h in self.source_events:
            self.source_events[h] = event

        self.info(f"Brute-forcing subdomains for {query} (source: {event.data})")
        for hostname in await self.massdns(query, self.helpers.read_file(self.subdomain_file)):
            self.emit_result(hostname, event, query)

    def abort_if(self, event):
        if not event.scope_distance == 0:
            return True, "event is not in scope"
        if "wildcard" in event.tags:
            return True, "event is a wildcard"

    def emit_result(self, result, source_event, query):
        if not result == source_event:
            kwargs = {"abort_if": self.abort_if}
            self.emit_event(result, "DNS_NAME", source_event, **kwargs)

    def already_processed(self, hostname):
        if hash(hostname) in self.processed:
            return True
        return False

    async def massdns(self, domain, subdomains):
        abort_msg = f"Aborting massdns on {domain} due to false positives"
        if await self._canary_check(domain):
            self.info(abort_msg)
            return []
        results = [l async for l in self._massdns(domain, subdomains)]
        if len(results) > 50:
            if await self._canary_check(domain):
                self.info(abort_msg)
                return []
        self.verbose(f"Resolving batch of {len(results):,} results")
        resolved = dict(
            [l async for l in self.helpers.resolve_batch(results, type=("A", "AAAA", "CNAME"), cache_result=True)]
        )
        resolved = {k: v for k, v in resolved.items() if v}
        for hostname in resolved:
            self.add_found(hostname)
        return list(resolved)

    async def _canary_check(self, domain, num_checks=50):
        random_subdomains = list(self.gen_random_subdomains(num_checks))
        self.verbose(f"Testing {len(random_subdomains):,} canaries against {domain}")
        canary_results = [l async for l in self._massdns(domain, random_subdomains)]
        async for result in self.helpers.resolve_batch(canary_results):
            if result:
                return True
        # for result in canary_results:
        #     if await self.helpers.resolve(result):
        #         return True
        return False

    async def _massdns(self, domain, subdomains):
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
        if self.scan.stopping:
            return

        domain_wildcard_rdtypes = set()
        for domain, rdtypes in (await self.helpers.is_wildcard_domain(domain)).items():
            for rdtype, results in rdtypes.items():
                if results:
                    domain_wildcard_rdtypes.add(rdtype)

        command = (
            "massdns",
            "-r",
            self.resolver_file,
            "-s",
            self.max_resolvers,
            "-t",
            "A",
            "-t",
            "AAAA",
            "-o",
            "J",
            "-q",
        )
        subdomains = self.gen_subdomains(subdomains, domain)
        hosts_yielded = set()
        async for line in self.helpers.run_live(command, stderr=subprocess.DEVNULL, input=subdomains):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            answers = j.get("data", {}).get("answers", [])
            if type(answers) == list and len(answers) > 0:
                answer = answers[0]
                hostname = answer.get("name", "").strip(".").lower()
                if hostname.endswith(f".{domain}"):
                    data = answer.get("data", "")
                    rdtype = answer.get("type", "").upper()
                    # avoid garbage answers like this:
                    # 8AAAA queries have been locally blocked by dnscrypt-proxy/Set block_ipv6 to false to disable this feature
                    if data and rdtype and not " " in data:
                        # skip wildcards
                        if rdtype in domain_wildcard_rdtypes:
                            # skip wildcard checking on multi-level subdomains for performance reasons
                            stem = hostname.split(domain)[0].strip(".")
                            if "." in stem:
                                self.debug(
                                    f"Skipping {hostname}:{rdtype} because it may be a wildcard (reason: performance)"
                                )
                                continue
                            wildcard_rdtypes = await self.helpers.is_wildcard(hostname, ips=(data,))
                            if rdtype in wildcard_rdtypes:
                                self.debug(f"Skipping {hostname}:{rdtype} because it's a wildcard")
                                continue
                        hostname_hash = hash(hostname)
                        if hostname_hash not in hosts_yielded:
                            hosts_yielded.add(hostname_hash)
                            yield hostname

    async def finish(self):
        found = sorted(self.found.items(), key=lambda x: len(x[-1]), reverse=True)
        # if we have a lot of rounds to make, don't try mutations on less-populated domains
        trimmed_found = []
        if found:
            avg_subdomains = sum([len(subdomains) for domain, subdomains in found[:50]]) / len(found[:50])
            for i, (domain, subdomains) in enumerate(found):
                # accept domains that are in the top 50 or have more than 5 percent of the average number of subdomains
                if i < 50 or (len(subdomains) > 1 and len(subdomains) >= (avg_subdomains * 0.05)):
                    trimmed_found.append((domain, subdomains))
                else:
                    self.verbose(
                        f"Skipping mutations on {domain} because it only has {len(subdomains):,} subdomain(s) (avg: {avg_subdomains:,})"
                    )

        base_mutations = set()
        try:
            for i, (domain, subdomains) in enumerate(trimmed_found):
                self.verbose(f"{domain} has {len(subdomains):,} subdomains")
                # keep looping as long as we're finding things
                while 1:
                    max_mem_percent = 90
                    mem_status = self.helpers.memory_status()
                    # abort if we don't have the memory
                    mem_percent = mem_status.percent
                    if mem_percent > max_mem_percent:
                        free_memory = mem_status.available
                        free_memory_human = self.helpers.bytes_to_human(free_memory)
                        assert (
                            False
                        ), f"Cannot proceed with DNS mutations because system memory is at {mem_percent:.1f}% ({free_memory_human} remaining)"

                    query = domain
                    domain_hash = hash(domain)
                    if self.scan.stopping:
                        return

                    mutations = set(base_mutations)

                    def add_mutation(_domain_hash, m):
                        h = hash((_domain_hash, m))
                        if h not in self.mutations_tried:
                            self.mutations_tried.add(h)
                            mutations.add(m)

                    # try every subdomain everywhere else
                    for _domain, _subdomains in found:
                        if _domain == domain:
                            continue
                        for s in _subdomains:
                            first_segment = s.split(".")[0]
                            # skip stuff with lots of numbers (e.g. PTRs)
                            digits = self.digit_regex.findall(first_segment)
                            excessive_digits = len(digits) > 2
                            long_digits = any(len(d) > 3 for d in digits)
                            if excessive_digits or long_digits:
                                continue
                            add_mutation(domain_hash, first_segment)
                            for word in self.helpers.extract_words(
                                first_segment, word_regexes=self.helpers.word_cloud.dns_mutator.extract_word_regexes
                            ):
                                add_mutation(domain_hash, word)

                    # numbers + devops mutations
                    for mutation in self.helpers.word_cloud.mutations(
                        subdomains, cloud=False, numbers=3, number_padding=1
                    ):
                        for delimiter in ("", ".", "-"):
                            m = delimiter.join(mutation).lower()
                            add_mutation(domain_hash, m)

                    # special dns mutator
                    for subdomain in self.helpers.word_cloud.dns_mutator.mutations(
                        subdomains, max_mutations=self.max_mutations
                    ):
                        add_mutation(domain_hash, subdomain)

                    if mutations:
                        self.info(f"Trying {len(mutations):,} mutations against {domain} ({i+1}/{len(found)})")
                        results = list(await self.massdns(query, mutations))
                        for hostname in results:
                            source_event = self.get_source_event(hostname)
                            if source_event is None:
                                self.warning(f"Could not correlate source event from: {hostname}")
                                continue
                            self.emit_result(hostname, source_event, query)
                        if results:
                            continue
                    break
        except AssertionError as e:
            self.warning(e)

    def add_found(self, host):
        if not isinstance(host, str):
            host = host.data
        if self.helpers.is_subdomain(host):
            subdomain, domain = host.split(".", 1)
            if not self.helpers.is_ptr(subdomain):
                try:
                    self.found[domain].add(subdomain)
                except KeyError:
                    self.found[domain] = set((subdomain,))

    async def gen_subdomains(self, prefixes, domain):
        for p in prefixes:
            d = f"{p}.{domain}"
            yield d

    def gen_random_subdomains(self, n=50):
        delimeters = (".", "-")
        lengths = list(range(10, 20))
        for i in range(0, n):
            d = delimeters[i % len(delimeters)]
            l = lengths[i % len(lengths)]
            segments = list(random.choice(self.devops_mutations) for _ in range(l))
            subdomains = d.join(segments)
            yield subdomains

    def get_source_event(self, hostname):
        for p in self.helpers.domain_parents(hostname):
            try:
                return self.source_events[hash(p)]
            except KeyError:
                continue
