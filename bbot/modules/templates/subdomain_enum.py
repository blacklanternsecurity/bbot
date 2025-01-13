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

    # set qsize to 10. this helps combat rate limiting by ensuring the next query doesn't execute
    # until the result from the previous queue have been consumed by the scan
    # we don't use 1 because it causes delays due to the asyncio.sleep; 10 gives us reasonable buffer room
    _qsize = 10

    # how to deduplicate incoming events
    # options:
    #   "highest_parent": dedupe by highest parent (highest parent of www.api.test.evilcorp.com is evilcorp.com)
    #   "lowest_parent": dedupe by lowest parent (lowest parent of www.api.test.evilcorp.com is api.test.evilcorp.com)
    dedup_strategy = "highest_parent"

    # how many results to request per API call
    page_size = 100
    # arguments to pass to api_page_iter
    api_page_iter_kwargs = {}

    @property
    def source_pretty_name(self):
        return f"{self.__class__.__name__} API"

    def _incoming_dedup_hash(self, event):
        """
        Determines the criteria for what is considered to be a duplicate event if `accept_dupes` is False.
        """
        return hash(self.make_query(event)), f"dedup_strategy={self.dedup_strategy}"

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
                        await self.emit_event(
                            hostname,
                            "DNS_NAME",
                            event,
                            abort_if=self.abort_if,
                            context=f'{{module}} searched {self.source_pretty_name} for "{query}" and found {{event.type}}: {{event.data}}',
                        )

    async def handle_event_paginated(self, event):
        query = self.make_query(event)
        async for result_batch in self.query_paginated(query):
            for hostname in set(result_batch):
                try:
                    hostname = self.helpers.validators.validate_host(hostname)
                except ValueError as e:
                    self.verbose(e)
                    continue
                if hostname and hostname.endswith(f".{query}") and not hostname == event.data:
                    await self.emit_event(
                        hostname,
                        "DNS_NAME",
                        event,
                        abort_if=self.abort_if,
                        context=f'{{module}} searched {self.source_pretty_name} for "{query}" and found {{event.type}}: {{event.data}}',
                    )

    async def request_url(self, query):
        url = self.make_url(query)
        return await self.api_request(url)

    def make_url(self, query):
        return f"{self.base_url}/subdomains/{self.helpers.quote(query)}"

    def make_query(self, event):
        query = event.data
        parents = list(self.helpers.domain_parents(event.data))
        if self.dedup_strategy == "highest_parent":
            parents = list(reversed(parents))
        elif self.dedup_strategy == "lowest_parent":
            pass
        else:
            raise ValueError('self.dedup_strategy attribute must be set to either "highest_parent" or "lowest_parent"')
        for p in parents:
            if self.scan.in_scope(p):
                query = p
                break
        return ".".join([s for s in query.split(".") if s != "_wildcard"])

    async def parse_results(self, r, query=None):
        json = r.json()
        if json:
            for hostname in json:
                yield hostname

    async def query(self, query, request_fn=None, parse_fn=None):
        if request_fn is None:
            request_fn = self.request_url
        if parse_fn is None:
            parse_fn = self.parse_results
        try:
            response = await request_fn(query)
            if response is None:
                self.info(f'Query "{query}" failed (no response)')
                return []
            try:
                results = list(await parse_fn(response, query))
            except Exception as e:
                if response:
                    self.info(
                        f'Error parsing results for query "{query}" (status code {response.status_code})', trace=True
                    )
                    self.log.trace(repr(response.text))
                else:
                    self.info(f'Error parsing results for "{query}": {e}', trace=True)
                return
            if results:
                return results
            self.debug(f'No results for "{query}"')
        except Exception as e:
            self.info(f"Error retrieving results for {query}: {e}", trace=True)

    async def query_paginated(self, query):
        url = self.make_url(query)
        agen = self.api_page_iter(url, page_size=self.page_size, **self.api_page_iter_kwargs)
        try:
            async for response in agen:
                subdomains = await self.parse_results(response, query)
                self.verbose(f'Got {len(subdomains):,} subdomains for "{query}"')
                if not subdomains:
                    break
                yield subdomains
        finally:
            await agen.aclose()

    async def _is_wildcard(self, query):
        rdtypes = ("A", "AAAA", "CNAME")
        if self.helpers.is_dns_name(query):
            for wildcard_rdtypes in (await self.helpers.is_wildcard_domain(query, rdtypes=rdtypes)).values():
                if any(t in wildcard_rdtypes for t in rdtypes):
                    return True
        return False

    async def filter_event(self, event):
        query = self.make_query(event)
        # check if wildcard
        is_wildcard = await self._is_wildcard(query)
        # check if cloud
        is_cloud = False
        if any(t.startswith("cloud-") for t in event.tags):
            is_cloud = True
        # reject if it's a cloud resource and not in our target
        if is_cloud and event not in self.scan.target.whitelist:
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
