############################################################
#                                                          #
#                                                          #
#    [-] Processing BuiltWith Domains Output               #
#                                                          #
#    [-] 2022.08.19                                        #
#          V05                                             #
#          Black Lantern Security (BLSOPS)                 #
#                                                          #
#                                                          #
############################################################

from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class builtwith(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Builtwith.com for subdomains",
        "created_date": "2022-08-23",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "redirects": True}
    options_desc = {"api_key": "Builtwith API key", "redirects": "Also look up inbound and outbound redirects"}
    base_url = "https://api.builtwith.com"

    async def handle_event(self, event):
        query = self.make_query(event)
        # domains
        subdomains = await self.query(query, parse_fn=self.parse_domains, request_fn=self.request_domains)
        if subdomains:
            for s in subdomains:
                if s != event:
                    await self.emit_event(
                        s,
                        "DNS_NAME",
                        parent=event,
                        context=f'{{module}} queried the BuiltWith API for "{query}" and found {{event.type}}: {{event.data}}',
                    )
        # redirects
        if self.config.get("redirects", True):
            redirects = await self.query(query, parse_fn=self.parse_redirects, request_fn=self.request_redirects)
            if redirects:
                for r in redirects:
                    if r != event:
                        await self.emit_event(
                            r,
                            "DNS_NAME",
                            parent=event,
                            tags=["affiliate"],
                            context=f'{{module}} queried the BuiltWith redirect API for "{query}" and found redirect to {{event.type}}: {{event.data}}',
                        )

    async def request_domains(self, query):
        url = f"{self.base_url}/v20/api.json?KEY={{api_key}}&LOOKUP={query}&NOMETA=yes&NOATTR=yes&HIDETEXT=yes&HIDEDL=yes"
        return await self.api_request(url)

    async def request_redirects(self, query):
        url = f"{self.base_url}/redirect1/api.json?KEY={{api_key}}&LOOKUP={query}"
        return await self.api_request(url)

    def parse_domains(self, r, query):
        """
        This method returns a set of subdomains.
        Each subdomain is an "FQDN" that was reported in the "Detailed Technology Profile" page on builtwith.com

        Parameters
        ----------
        r (requests Response): The raw requests response from the API
        query (string): The query used against the API
        """
        results_set = set()
        json = r.json()
        if json and isinstance(json, dict):
            results = json.get("Results", [])
            if results:
                for result in results:
                    for chunk in result.get("Result", {}).get("Paths", []):
                        domain = chunk.get("Domain", "")
                        subdomain = chunk.get("SubDomain", "")
                        if domain:
                            if subdomain:
                                domain = f"{subdomain}.{domain}"
                            results_set.add(domain)
            else:
                errors = json.get("Errors", [{}])
                if errors:
                    error = errors[0].get("Message", "Unknown Error")
                    self.verbose(f"No results for {query}: {error}")
        return results_set

    def parse_redirects(self, r, query):
        """
        This method creates a set.
        Each entry in the set is either an Inbound or Outbound Redirect reported in the "Redirect Profile" page on builtwith.com

        Parameters
        ----------
        r (requests Response): The raw requests response from the API
        query (string): The query used against the API

        Returns
        -------
        results (set)
        """
        results = set()
        json = r.json()
        if json and isinstance(json, dict):
            inbound = json.get("Inbound", [])
            outbound = json.get("Outbound", [])
            if inbound:
                for i in inbound:
                    domain = i.get("Domain", "")
                    if domain:
                        results.add(domain)
            if outbound:
                for o in outbound:
                    domain = o.get("Domain", "")
                    if domain:
                        results.add(domain)
        if not results:
            error = json.get("error", "")
            if error:
                self.warning(f"No results for {query}: {error}")
        return results
