from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class zoomeye(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query ZoomEye's API for subdomains",
        "created_date": "2022-08-03",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "max_pages": 20, "include_related": False}
    options_desc = {
        "api_key": "ZoomEye API key",
        "max_pages": "How many pages of results to fetch",
        "include_related": "Include domains which may be related to the target",
    }

    base_url = "https://api.zoomeye.hk"

    async def setup(self):
        self.max_pages = self.config.get("max_pages", 20)
        self.include_related = self.config.get("include_related", False)
        return await super().setup()

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["API-KEY"] = self.api_key
        return url, kwargs

    async def ping(self):
        url = f"{self.base_url}/resources-info"
        r = await self.api_request(url, retry_on_http_429=False)
        assert int(r.json()["quota_info"]["remain_total_quota"]) > 0, "No quota remaining"

    async def handle_event(self, event):
        query = self.make_query(event)
        results = await self.query(query)
        if results:
            for hostname in results:
                if hostname == event:
                    continue
                tags = []
                if not hostname.endswith(f".{query}"):
                    tags = ["affiliate"]
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    event,
                    tags=tags,
                    context=f'{{module}} searched ZoomEye API for "{query}" and found {{event.type}}: {{event.data}}',
                )

    async def query(self, query):
        results = set()
        query_type = 0 if self.include_related else 1
        url = f"{self.base_url}/domain/search?q={self.helpers.quote(query)}&type={query_type}&page=" + "{page}"
        i = 0
        agen = self.api_page_iter(url)
        try:
            async for j in agen:
                r = list(await self.parse_results(j))
                if r:
                    results.update(set(r))
                if not r or i >= (self.max_pages - 1):
                    break
                i += 1
        finally:
            await agen.aclose()
        return results

    async def parse_results(self, r):
        results = set()
        for entry in r.get("list", []):
            results.add(entry["name"])
        return results
