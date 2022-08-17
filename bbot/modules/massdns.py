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
        {"name": "install dev tools", "package": {"name": ["gcc", "git", "make"], "state": "present"}, "become": True},
        {
            "name": "Download massdns source code",
            "git": {
                "repo": "https://github.com/blechschmidt/massdns.git",
                "dest": "{BBOT_TEMP}/massdns",
                "single_branch": True,
                "version": "master",
            },
        },
        {
            "name": "Build massdns",
            "command": {"chdir": "{BBOT_TEMP}/massdns", "cmd": "make", "creates": "{BBOT_TEMP}/massdns/bin/massdns"},
        },
        {
            "name": "Install massdns",
            "copy": {"src": "{BBOT_TEMP}/massdns/bin/massdns", "dest": "{BBOT_TOOLS}/", "mode": "u+x,g+x,o+x"},
        },
    ]

    def setup(self):
        self.found = dict()
        self.mutations_tried = set()
        self.source_events = dict()
        self.subdomain_file = self.helpers.wordlist(self.config.get("wordlist"))
        return super().setup()

    def handle_event(self, event):
        query = self.make_query(event)
        h = hash(query)
        if not h in self.source_events:
            self.source_events[h] = event

        # wildcard sanity check
        is_wildcard, _ = self.helpers.is_wildcard(f"{self.helpers.rand_string()}.{query}")
        if is_wildcard:
            self.debug(f"Skipping wildcard: {query}")
            return

        for hostname in self.massdns(query, self.helpers.read_file(self.subdomain_file)):
            self.emit_result(hostname, event, query)

    def emit_result(self, result, source_event, query):
        if not result == source_event:
            kwargs = {"abort_if": lambda e: any([x in e.tags for x in ("wildcard", "unresolved")])}
            if result.endswith(f".{query}"):
                kwargs["on_success_callback"] = self.add_found
            self.emit_event(result, "DNS_NAME", source_event, **kwargs)

    def massdns(self, domain, subdomains):
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

        self.debug(f"Brute-forcing subdomains for {domain}")
        command = (
            "massdns",
            "-r",
            self.helpers.dns.mass_resolver_file,
            "-s",
            self.config.get("max_resolvers", 1000),
            "-t",
            "A",
            "-t",
            "AAAA",
            "-o",
            "J",
            "-q",
        )
        subdomains = self.gen_subdomains(subdomains, domain)
        for line in self.helpers.run_live(command, stderr=subprocess.DEVNULL, input=subdomains):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            answers = j.get("data", {}).get("answers", [])
            if type(answers) == list:
                for answer in answers:
                    hostname = answer.get("name", "")
                    if hostname:
                        data = answer.get("data", "")
                        # avoid garbage answers like this:
                        # 8AAAA queries have been locally blocked by dnscrypt-proxy/Set block_ipv6 to false to disable this feature
                        if " " not in data:
                            yield hostname.rstrip(".")

    def finish(self):
        found = list(self.found.items())

        base_mutations = set()
        for domain, subdomains in found:
            base_mutations.update(set(subdomains))

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
            self.verbose(f"Trying {len(mutations):,} mutations against {domain} ({i+1}/{len(found)})")
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
            yield f"{p}.{domain}"

    def get_source_event(self, hostname):
        for p in self.helpers.domain_parents(hostname):
            try:
                return self.source_events[hash(p)]
            except KeyError:
                continue
