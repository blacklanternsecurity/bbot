from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class Trickest(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Trickest's API for subdomains",
        "author": "@amiremami",
        "created_date": "2024-07-27",
        "auth_required": True,
    }
    options = {
        "api_key": "",
    }
    options_desc = {
        "api_key": "Trickest API key",
    }

    base_url = "https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be"
    dataset_id = "a0a49ca9-03bb-45e0-aa9a-ad59082ebdfc"
    page_size = 50

    async def ping(self):
        self.headers = {"Authorization": f"Token {self.api_key}"}
        url = f"{self.base_url}/dataset"
        response = await self.helpers.request(url, headers=self.headers)
        status_code = getattr(response, "status_code", 0)
        if status_code != 200:
            response_text = getattr(response, "text", "no response from server")
            return False, response_text
        return True

    async def handle_event(self, event):
        query = self.make_query(event)
        async for result_batch in self.query(query):
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

    async def query(self, query):
        url = f"{self.base_url}/view?q=hostname%20~%20%22.{self.helpers.quote(query)}%22"
        url += f"&dataset_id={self.dataset_id}"
        url += "&limit={page_size}&offset={offset}&select=hostname&orderby=hostname"
        agen = self.helpers.api_page_iter(url, headers=self.headers, page_size=self.page_size)
        try:
            async for response in agen:
                subdomains = self.parse_results(response)
                self.verbose(f'Got {len(subdomains):,} subdomains for "{query}"')
                if not subdomains:
                    break
                yield subdomains
        finally:
            agen.aclose()

    def parse_results(self, j):
        results = j.get("results", [])
        subdomains = set()
        for item in results:
            hostname = item.get("hostname", "")
            if hostname:
                subdomains.add(hostname)
        return subdomains
