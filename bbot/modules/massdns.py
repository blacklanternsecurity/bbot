import json
import subprocess

from .base import BaseModule


class massdns(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    options = {
        "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
        "max_resolvers": 1000,
    }
    options_desc = {"wordlist": "Subdomain wordlist URL", "max_resolvers": "Number of concurrent massdns resolvers"}
    subdomain_file = None
    target_only = True
    flags = ["brute_force"]

    def setup(self):

        self.processed = set()
        self.found = dict()
        self.subdomain_file = self.helpers.download(
            self.config.get("wordlist", self.options.get("wordlist")), cache_hrs=720
        )
        if not self.subdomain_file:
            self.error("Failed to download wordlist")
            return False
        return True

    def filter_event(self, event):
        if "wildcard" in event.tags:
            return False
        if "target" in event.tags:
            return True
        elif self.helpers.parent_domain(event.data) not in self.processed:
            return True
        return False

    def handle_event(self, event):

        if not "target" in event.tags:
            query = self.helpers.parent_domain(event.data)
        else:
            query = str(event.data).lower()

        if query not in self.processed:
            self.processed.add(query)

        if self.helpers.is_wildcard(f"geezrick.{query}"):
            self.debug(f"Skipping wildcard: {query}")
            return

        for hostname in self.massdns(query, self.subdomain_file):
            self.emit_event(
                hostname,
                "DNS_NAME",
                event,
                abort_if_tagged=("wildcard", "unresolved"),
                on_success_callback=self.add_found,
            )

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
            self.helpers.dns.resolver_file,
            "-s",
            self.config.get("max_resolvers", 1000),
            "-t",
            "A",
            "-o",
            "J",
        )
        if type(subdomains) == str:
            subdomains = self.helpers.read_file(subdomains)
        subdomains = self.gen_subdomains(subdomains, domain)
        for line in self.helpers.run_live(command, stderr=subprocess.DEVNULL, input=subdomains):
            try:
                j = json.loads(line)
            except json.decoder.JSONDecodeError:
                self.debug(f"Failed to decode line: {line}")
                continue
            status = j.get("status", "")
            if status == "NOERROR":
                hostname = j.get("name", "")
                if hostname:
                    yield hostname.rstrip(".")

    def finish(self):
        base_mutations = set()
        for domain, subdomains in list(self.found.items()):
            base_mutations.update(set([s[0] for s in subdomains]))

        for domain, subdomains in list(self.found.items()):
            mutations = set(base_mutations)
            for mutation in self.helpers.word_cloud.mutations(set([s[0] for s in subdomains])):
                for delimiter in ("", ".", "-"):
                    mutations.add(delimiter.join(mutation))
            for hostname in self.massdns(domain, mutations):
                event = next(iter(self.found[domain]))[-1]
                self.emit_event(
                    hostname,
                    "DNS_NAME",
                    event,
                    abort_if_tagged=("wildcard", "unresolved"),
                    on_success_callback=self.add_found,
                )

    def add_found(self, event):
        if self.helpers.is_subdomain(event.data):
            subdomain, domain = event.data.split(".", 1)
            try:
                self.found[domain].add((subdomain, event))
            except KeyError:
                self.found[domain] = set(((subdomain, event),))

    def is_found(self, hostname):
        subdomain, domain = self.helpers.split_domain(hostname)
        return subdomain in self.found.get(domain, [])

    def gen_subdomains(self, prefixes, domain):
        for p in prefixes:
            yield f"{p}.{domain}"
