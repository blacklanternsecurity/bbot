from bbot.modules.base import BaseModule


class crobat(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by several other modules including sublist3r, dnsdumpster, etc.
    """

    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query Project Crobat for subdomains"}

    base_url = "https://sonar.omnisint.io"

    # this helps combat rate limiting by ensuring that a query doesn't execute
    # until the queue is ready to receive its results
    _qsize = 1

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        """
        Accept DNS_NAMEs that are either directly targets, or indirectly
        in scope by resolving to in-scope IPs.

        Kill wildcards with fire.

        This filter_event is used across many modules
        """
        query = self.make_query(event)
        if self.already_processed(query):
            return False, "Event was already processed"
        if not "target" in event.tags:
            if "unresolved" in event.tags:
                return False, "Event is unresolved"
            if any(t.startswith("cloud-") for t in event.tags):
                return False, "Event is a cloud resource and not a direct target"
        for domain, wildcard_rdtypes in self.helpers.is_wildcard_domain(query).items():
            if any(t in wildcard_rdtypes for t in ("A", "AAAA", "CNAME")):
                return False, "Event is a wildcard domain"
        if any(t in event.tags for t in ("a-error", "aaaa-error")):
            return False, "Event has a DNS resolution error"
        self.processed.add(hash(query))
        return True

    def already_processed(self, hostname):
        for parent in self.helpers.domain_parents(hostname, include_self=True):
            if hash(parent) in self.processed:
                return True
        return False

    def abort_if(self, event):
        # this helps weed out unwanted results when scanning IP_RANGES and wildcard domains
        return "in-scope" not in event.tags or "wildcard" in event.tags

    def handle_event(self, event):
        query = self.make_query(event)
        results = self.query(query)
        if results:
            for hostname in results:
                if not hostname == event:
                    self.emit_event(hostname, "DNS_NAME", event, abort_if=self.abort_if)

    def request_url(self, query):
        url = f"{self.base_url}/subdomains/{self.helpers.quote(query)}"
        return self.helpers.request(url)

    def make_query(self, event):
        if "target" in event.tags:
            query = str(event.data)
        else:
            query = self.helpers.parent_domain(event.data).lower()
        return ".".join([s for s in query.split(".") if s != "_wildcard"])

    def parse_results(self, r, query=None):
        json = r.json()
        if json:
            for hostname in json:
                yield hostname

    def query(self, query, parse_fn=None, request_fn=None):
        if parse_fn is None:
            parse_fn = self.parse_results
        if request_fn is None:
            request_fn = self.request_url
        try:
            results = list(parse_fn(request_fn(query), query))
            if results:
                return results
            self.debug(f'No results for "{query}"')
        except Exception:
            self.verbose(f"Error retrieving results for {query}")
            self.trace()
