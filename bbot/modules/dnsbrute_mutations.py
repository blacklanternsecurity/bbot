from bbot.modules.base import BaseModule


class dnsbrute_mutations(BaseModule):
    flags = ["subdomain-enum", "active", "aggressive", "slow"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Brute-force subdomains with massdns + target-specific mutations",
        "author": "@TheTechromancer",
        "created_date": "2024-04-25",
    }
    options = {
        "max_mutations": 100,
    }
    options_desc = {
        "max_mutations": "Maximum number of target-specific mutations to try per subdomain",
    }
    deps_common = ["massdns"]
    _qsize = 10000

    async def setup(self):
        self.found = {}
        self.parent_events = {}
        self.max_mutations = self.config.get("max_mutations", 500)
        # 800M bits == 100MB bloom filter == 10M entries before false positives start emerging
        self.mutations_tried = self.helpers.bloom_filter(800000000)
        self._mutation_run_counter = {}
        return True

    async def handle_event(self, event):
        # here we don't brute-force, we just add the subdomain to our end-of-scan
        host = str(event.host)
        self.parent_events[host] = event
        if self.helpers.is_subdomain(host):
            subdomain, domain = host.split(".", 1)
            if not self.helpers.dns.brute.has_excessive_digits(subdomain):
                try:
                    self.found[domain].add(subdomain)
                except KeyError:
                    self.found[domain] = {subdomain}

    def get_parent_event(self, subdomain):
        parent_host = self.helpers.closest_match(subdomain, self.parent_events)
        return self.parent_events[parent_host]

    async def finish(self):
        """
        TODO: speed up this loop.
            We should see if we can combine multiple runs together instead of running them each individually.
        """
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
                    query = domain

                    mutations = set(base_mutations)

                    def add_mutation(m):
                        h = f"{m}.{domain}"
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
                            if self.helpers.dns.brute.has_excessive_digits(first_segment):
                                continue
                            add_mutation(first_segment)
                            for word in self.helpers.extract_words(
                                first_segment, word_regexes=self.helpers.word_cloud.dns_mutator.extract_word_regexes
                            ):
                                add_mutation(word)

                    # numbers + devops mutations
                    for mutation in self.helpers.word_cloud.mutations(
                        subdomains, cloud=False, numbers=3, number_padding=1
                    ):
                        for delimiter in ("", ".", "-"):
                            m = delimiter.join(mutation).lower()
                            add_mutation(m)

                    # special dns mutator
                    for subdomain in self.helpers.word_cloud.dns_mutator.mutations(
                        subdomains, max_mutations=self.max_mutations
                    ):
                        add_mutation(subdomain)

                    # skip if there's hardly any mutations
                    if len(mutations) < 10:
                        self.verbose(
                            f"Skipping {len(mutations):,} mutations against {domain} because there are less than 10"
                        )
                        break

                    if mutations:
                        self.info(f"Trying {len(mutations):,} mutations against {domain} ({i+1}/{len(trimmed_found)})")
                        results = await self.helpers.dns.brute(self, query, mutations)
                        try:
                            mutation_run = self._mutation_run_counter[domain]
                        except KeyError:
                            self._mutation_run_counter[domain] = mutation_run = 1
                        self._mutation_run_counter[domain] += 1
                        for hostname in results:
                            parent_event = self.get_parent_event(hostname)
                            mutation_run_ordinal = self.helpers.integer_to_ordinal(mutation_run)
                            await self.emit_event(
                                hostname,
                                "DNS_NAME",
                                parent=parent_event,
                                tags=[f"mutation-{mutation_run}"],
                                abort_if=self.abort_if,
                                context=f'{{module}} found a mutated subdomain of "{parent_event.host}" on its {mutation_run_ordinal} run: {{event.type}}: {{event.data}}',
                            )
                        if results:
                            continue
                    break
        except AssertionError as e:
            self.warning(e)

    def abort_if(self, event):
        if not event.scope_distance == 0:
            return True, "event is not in scope"
        if "wildcard" in event.tags:
            return True, "event is a wildcard"
        if "unresolved" in event.tags:
            return True, "event is unresolved"
        return False, ""
