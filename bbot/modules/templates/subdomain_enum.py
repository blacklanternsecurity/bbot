from bbot.modules.base import BaseModule


class subdomain_enum(BaseModule):
    """
    A typical free API-based subdomain enumeration module
    Inherited by many other modules including sublist3r, dnsdumpster, etc.
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query an API for subdomains"}

    base_url = "https://api.example.com"

    # set module error state after this many failed requests in a row
    abort_after_failures = 5
    # whether to reject wildcard DNS_NAMEs
    reject_wildcards = "strict"
    # this helps combat rate limiting by ensuring that a query doesn't execute
    # until the queue is ready to receive its results
    _qsize = 1

    async def setup(self):
        self.processed = set()
        return True

    async def handle_event(self, event):
        query = self.make_query(event)
        results = await self.query(query)
        if results:
            for hostname in set(results):
                if hostname:
                    try:
                        hostname = self.helpers.validators.validate_host(hostname)
                    except ValueError as e:
                        self.verbose(e)
                        continue
                    if hostname and hostname.endswith(f".{query}") and not hostname == event.data:
                        await self.emit_event(hostname, "DNS_NAME", event, abort_if=self.abort_if)

    async def request_url(self, query):
        url = f"{self.base_url}/subdomains/{self.helpers.quote(query)}"
        return await self.request_with_fail_count(url)

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

    async def query(self, query, parse_fn=None, request_fn=None):
        if parse_fn is None:
            parse_fn = self.parse_results
        if request_fn is None:
            request_fn = self.request_url
        try:
            response = await request_fn(query)
            if response is None:
                self.info(f'Query "{query}" failed (no response)')
                return []
            try:
                results = list(parse_fn(response, query))
            except Exception as e:
                if response:
                    self.info(
                        f'Error parsing results for query "{query}" (status code {response.status_code})', trace=True
                    )
                    self.log.trace(response.text)
                else:
                    self.info(f'Error parsing results for "{query}": {e}', trace=True)
                return
            if results:
                return results
            self.debug(f'No results for "{query}"')
        except Exception as e:
            self.info(f"Error retrieving results for {query}: {e}", trace=True)

    async def _is_wildcard(self, query):
        if self.helpers.is_dns_name(query):
            for domain, wildcard_rdtypes in (await self.helpers.is_wildcard_domain(query)).items():
                if any(t in wildcard_rdtypes for t in ("A", "AAAA", "CNAME")):
                    return True
        return False

    async def filter_event(self, event):
        """
        This filter_event is used across many modules
        """
        query = self.make_query(event)
        # reject if already processed
        if self.already_processed(query):
            return False, "Event was already processed"
        eligible, reason = await self.eligible_for_enumeration(event)
        if eligible:
            self.processed.add(hash(query))
            return True, reason
        return False, reason

    async def eligible_for_enumeration(self, event):
        query = self.make_query(event)
        # check if wildcard
        is_wildcard = await self._is_wildcard(query)
        # check if cloud
        is_cloud = False
        if any(t.startswith("cloud-") for t in event.tags):
            is_cloud = True
        # reject if it's a cloud resource and not in our target
        if is_cloud and event not in self.scan.target:
            return False, "Event is a cloud resource and not a direct target"
        # optionally reject events with wildcards / errors
        if self.reject_wildcards:
            if any(t in event.tags for t in ("a-error", "aaaa-error")):
                return False, "Event has a DNS resolution error"
            if self.reject_wildcards == "strict":
                if is_wildcard:
                    return False, "Event is a wildcard domain"
            elif self.reject_wildcards == "cloud_only":
                if is_wildcard and is_cloud:
                    return False, "Event is both a cloud resource and a wildcard domain"
        return True, ""

    def already_processed(self, hostname):
        for parent in self.helpers.domain_parents(hostname, include_self=True):
            if hash(parent) in self.processed:
                return True
        return False

    async def abort_if(self, event):
        # this helps weed out unwanted results when scanning IP_RANGES and wildcard domains
        if "in-scope" not in event.tags:
            return True
        return False


class subdomain_enum_apikey(subdomain_enum):
    """
    A typical module for authenticated, API-based subdomain enumeration
    Inherited by several other modules including securitytrails, c99.nl, etc.
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query API for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "API key"}

    async def setup(self):
        await super().setup()
        return await self.require_api_key()
