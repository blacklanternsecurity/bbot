from urllib.parse import quote

from .base import BaseModule


class crobat(BaseModule):
    """
    A typical API-based subdomain enumeration module
    Used by several other modules including sublist3r, dnsdumpster, and dnsgrep
    """

    flags = ["subdomain-enum"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    in_scope_only = True

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        if "target" in event.tags:
            return True
        # include out-of-scope DNS names that resolve to in-scope IPs
        elif event not in self.scan.target:
            if hash(self.helpers.parent_domain(event.data)) not in self.processed:
                return True
        return False

    def handle_event(self, event):
        if "target" in event.tags:
            query = str(event.data).lower()
        else:
            query = self.helpers.parent_domain(event.data).lower()

        if query not in self.processed:
            self.processed.add(hash(query))

            for hostname in self.query(query):
                if not hostname == event:
                    self.emit_event(hostname, "DNS_NAME", event, abort_if=lambda e: "in_scope" not in e.tags)
                else:
                    self.debug(f"Invalid subdomain: {hostname}")

    def query(self, query):
        results = self.helpers.request(f"https://sonar.omnisint.io/subdomains/{quote(query)}")
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
