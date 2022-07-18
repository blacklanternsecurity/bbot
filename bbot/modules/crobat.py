from bbot.modules.base import BaseModule


class crobat(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by several other modules including sublist3r, dnsdumpster, etc.
    """

    flags = ["subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]

    base_url = "https://sonar.omnisint.io"

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        """
        Accept DNS_NAMEs that are either directly targets, or indirectly
        in scope by resolving to in-scope IPs.

        This filter_event is used across many modules
        """
        query = self.make_query(event)
        if self.already_processed(query):
            return False
        is_wildcard, _ = self.helpers.is_wildcard(query)
        if is_wildcard:
            return False
        self.processed.add(hash(query))
        return True

    def make_query(self, event):
        if "target" in event.tags:
            return str(event.data)
        else:
            return self.helpers.parent_domain(event.data).lower()

    def already_processed(self, hostname):
        for parent in self.helpers.domain_parents(hostname, include_self=True):
            if hash(parent) in self.processed:
                return True
        return False

    def abort_if(self, event):
        # this help weed out unwanted results when scanning IP_RANGES
        return event.scope_distance >= self.scan.scope_search_distance

    def handle_event(self, event):
        query = self.make_query(event)
        results = self.query(query)
        if results:
            for hostname in results:
                if not hostname == event:
                    self.emit_event(hostname, "DNS_NAME", event, abort_if=self.abort_if)
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
