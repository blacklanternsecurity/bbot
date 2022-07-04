from .base import BaseModule


class crobat(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by several other modules including sublist3r, dnsdumpster, and dnsgrep
    """

    flags = ["subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    in_scope_only = True

    base_url = "https://sonar.omnisint.io"

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        valid = False
        if "target" in event.tags:
            query = str(event.data)
            valid = True
        else:
            if event not in self.scan.target:
                valid = True
            query = self.helpers.parent_domain(event.data)
        if valid and not self.already_processed(query):
            is_wildcard, _ = self.helpers.is_wildcard(query)
            if not is_wildcard:
                return True

    def already_processed(self, hostname):
        for parent in self.helpers.domain_parents(hostname, include_self=True):
            if hash(parent) in self.processed:
                return True
        return False

    def handle_event(self, event):
        if "target" in event.tags:
            query = str(event.data)
        else:
            query = self.helpers.parent_domain(event.data).lower()

        if self.already_processed(query):
            self.debug(f'Already processed "{query}", skipping')
            return

        self.processed.add(hash(query))

        results = self.query(query)
        if results:
            for hostname in results:
                if not hostname == event:
                    self.emit_event(hostname, "DNS_NAME", event, abort_if=lambda e: "in_scope" not in e.tags)
                else:
                    self.debug(f"Excluding self: {hostname}")

    def query(self, query):
        results = self.helpers.request(f"{self.base_url}/subdomains/{self.helpers.quote(query)}")
        try:
            json = results.json()
            if json:
                for hostname in json:
                    yield hostname
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving crobat domains for {query}")
            self.debug(traceback.format_exc())
