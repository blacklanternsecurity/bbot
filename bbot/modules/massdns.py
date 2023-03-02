import json
import subprocess

from .crobat import crobat


class massdns(crobat):
    flags = ["brute-force", "subdomain-enum", "passive", "slow", "aggressive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Brute-force subdomains with massdns (highly effective)"}
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "max_resolvers": 500,
    }
    options_desc = {"wordlist": "Subdomain wordlist URL", "max_resolvers": "Number of concurrent massdns resolvers"}
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
    _qsize = 100

    def setup(self):
        self.found = dict()
        self.mutations_tried = set()
        self.source_events = dict()
        self.subdomain_file = self.helpers.wordlist(self.config.get("wordlist"))
        self.max_resolvers = self.config.get("max_resolvers", 500)
        nameservers_url = (
            "https://raw.githubusercontent.com/blacklanternsecurity/public-dns-servers/master/nameservers.txt"
        )
        self.resolver_file = self.helpers.wordlist(
            nameservers_url,
            cache_hrs=24 * 7,
        )
        return super().setup()

    def filter_event(self, event):
        query = self.make_query(event)
        if self.already_processed(query):
            return False, "Event was already processed"
        is_cloud = False
        if any(t.startswith("cloud-") for t in event.tags):
            is_cloud = True
        is_wildcard = False
        for domain, wildcard_rdtypes in self.helpers.is_wildcard_domain(query).items():
            if any(t in wildcard_rdtypes for t in ("A", "AAAA", "CNAME")):
                is_wildcard = True
        if not "target" in event.tags:
            if "unresolved" in event.tags:
                return False, "Event is unresolved"
            if is_cloud:
                return False, "Event is a cloud resource and not a direct target"
        if is_wildcard and is_cloud:
            return False, "Event is both a cloud resource and a wildcard domain"
        self.processed.add(hash(query))
        return True

    def handle_event(self, event):
        query = self.make_query(event)
        h = hash(query)
        if not h in self.source_events:
            self.source_events[h] = event

        self.info(f"Brute-forcing subdomains for {query}")
        for hostname in self.massdns(query, self.helpers.read_file(self.subdomain_file)):
            self.emit_result(hostname, event, query)

    def abort_if(self, event):
        if not event.scope_distance == 0:
            return True, "event is not in scope"
        if "unresolved" in event.tags:
            return True, "event is unresolved"
        if "wildcard" in event.tags:
            return True, "event is a wildcard"
        if not any(x in event.tags for x in ("a-record", "aaaa-record", "cname-record")):
            return True, "event is not a valid record type"

    def emit_result(self, result, source_event, query):
        if not result == source_event:
            kwargs = {"abort_if": self.abort_if}
            if result.endswith(f".{query}"):
                kwargs["on_success_callback"] = self.add_found
            self.emit_event(result, "DNS_NAME", source_event, **kwargs)

    def already_processed(self, hostname):
        if hash(hostname) in self.processed:
            return True
        return False

    def massdns(self, domain, subdomains):
        canary_checks = 50
        canary_subdomains = [self.helpers.rand_string(10) for i in range(canary_checks)]
        self.verbose(f"Testing {canary_checks:,} canaries against {domain}")
        canary_results = list(self._massdns(domain, canary_subdomains))
        if len(canary_results) > 10:
            self.info(
                f"Aborting massdns run on {domain} due to {len(canary_results):,}/{canary_checks:,} false positives"
            )
        else:
            yield from self._massdns(domain, subdomains)

    def _massdns(self, domain, subdomains):
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
        for domain, rdtypes in self.helpers.is_wildcard_domain(domain).items():
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
        for line in self.helpers.run_live(command, stderr=subprocess.DEVNULL, input=subdomains):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            answers = j.get("data", {}).get("answers", [])
            if type(answers) == list and len(answers) > 0:
                answer = answers[0]
                hostname = answer.get("name", "")
                if hostname:
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
                            wildcard_rdtypes = self.helpers.is_wildcard(hostname, ips=(data,))
                            if rdtype in wildcard_rdtypes:
                                self.debug(f"Skipping {hostname}:{rdtype} because it's a wildcard")
                                continue
                        hostname = hostname.rstrip(".").lower()
                        hostname_hash = hash(hostname)
                        if hostname_hash not in hosts_yielded:
                            hosts_yielded.add(hostname_hash)
                            yield hostname

    def finish(self):
        found = list(self.found.items())

        base_mutations = set()
        for domain, subdomains in found:
            domain_hash = hash(domain)
            for s in subdomains:
                h = hash((domain_hash, (s,)))
                if not h in self.mutations_tried:
                    self.mutations_tried.add(h)
                    base_mutations.add(s)

        for i, (domain, subdomains) in enumerate(found):
            query = domain
            domain_hash = hash(domain)
            if self.scan.stopping:
                return
            mutations = set(base_mutations)
            for mutation in self.helpers.word_cloud.mutations(subdomains):
                h = hash((domain_hash, mutation))
                if h not in self.mutations_tried:
                    self.mutations_tried.add(h)
                    for delimiter in ("", ".", "-"):
                        m = delimiter.join(mutation).lower()
                        mutations.add(m)
            if mutations:
                self.info(f"Trying {len(mutations):,} mutations against {domain} ({i+1}/{len(found)})")
                for hostname in self.massdns(query, mutations):
                    source_event = self.get_source_event(hostname)
                    if source_event is None:
                        self.debug(f"Could not correlate source event from: {hostname}")
                        continue
                    self.emit_result(hostname, source_event, query)

    def add_found(self, event):
        if self.helpers.is_subdomain(event.data):
            subdomain, domain = event.data.split(".", 1)
            try:
                self.found[domain].add(subdomain)
            except KeyError:
                self.found[domain] = set((subdomain,))

    def gen_subdomains(self, prefixes, domain):
        for p in prefixes:
            d = f"{p}.{domain}"
            yield d

    def get_source_event(self, hostname):
        for p in self.helpers.domain_parents(hostname):
            try:
                return self.source_events[hash(p)]
            except KeyError:
                continue
