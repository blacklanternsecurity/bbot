from bbot.modules.templates.subdomain_enum import subdomain_enum


class sitedossier(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query sitedossier.com for subdomains",
        "created_date": "2023-08-04",
        "author": "@TheTechromancer",
    }

    base_url = "http://www.sitedossier.com/parentdomain"
    max_pages = 10

    async def handle_event(self, event):
        query = self.make_query(event)
        async for hostname in self.query(query):
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
                    context=f'{{module}} searched sitedossier.com for "{query}" and found {{event.type}}: {{event.data}}',
                )

    async def query(self, query, parse_fn=None, request_fn=None):
        results = set()
        base_url = f"{self.base_url}/{self.helpers.quote(query)}"
        url = str(base_url)
        for i, page in enumerate(range(1, 100 * self.max_pages + 2, 100)):
            self.verbose(f"Fetching page #{i+1} for {query}")
            if page > 1:
                url = f"{base_url}/{page}"
            response = await self.helpers.request(url)
            if response is None:
                self.info(f'Query "{query}" failed (no response)')
                break
            if response.status_code == 302:
                self.verbose("Hit rate limit captcha")
                break
            for match in await self.helpers.re.finditer_multi(self.scan.dns_regexes, response.text):
                hostname = match.group().lower()
                if hostname and hostname not in results:
                    results.add(hostname)
                    yield hostname
            if '<a href="/parentdomain/' not in response.text:
                self.debug(f"Next page not found")
                break
