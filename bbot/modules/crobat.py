from bbot.modules.base import BaseModule


class crobat(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by several other modules including sublist3r, dnsdumpster, etc.
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    # tag "subdomain-enum" removed 2023-02-24 because API is offline
    flags = ["passive", "safe"]
    meta = {"description": "Query Project Crobat for subdomains"}

    base_url = "https://sonar.omnisint.io"
    # set module error state after this many failed requests in a row
    abort_after_failures = 5
    # whether to reject wildcard DNS_NAMEs
    reject_wildcards = True
    # this helps combat rate limiting by ensuring that a query doesn't execute
    # until the queue is ready to receive its results
    _qsize = 1

    def setup(self):
        self.processed = set()
        self.http_timeout = self.scan.config.get("http_timeout", 10)
        self._failures = 0
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
        if self.reject_wildcards:
            if any(t in event.tags for t in ("a-wildcard-domain", "aaaa-wildcard-domain", "cname-wildcard-domain")):
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
        if "in-scope" not in event.tags:
            return True
        if any(t in event.tags for t in ("wildcard", "wildcard-domain")):
            return True
        return False

    def handle_event(self, event):
        query = self.make_query(event)
        results = self.query(query)
        if results:
            for hostname in set(results):
                if hostname:
                    hostname = hostname.lower()
                    if hostname.endswith(f".{query}") and not hostname == event.data:
                        self.emit_event(hostname, "DNS_NAME", event, abort_if=self.abort_if)

    def request_url(self, query):
        url = f"{self.base_url}/subdomains/{self.helpers.quote(query)}"
        return self.request_with_fail_count(url)

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
