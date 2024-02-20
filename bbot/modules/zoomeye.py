from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class zoomeye(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {"description": "Query ZoomEye's API for subdomains", "auth_required": True}
    options = {"api_key": "", "max_pages": 20, "include_related": False}
    options_desc = {
        "api_key": "ZoomEye API key",
        "max_pages": "How many pages of results to fetch",
        "include_related": "Include domains which may be related to the target",
    }

    base_url = "https://api.zoomeye.org"

    async def setup(self):
        self.max_pages = self.config.get("max_pages", 20)
        self.headers = {"API-KEY": self.config.get("api_key", "")}
        self.include_related = self.config.get("include_related", False)
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/resources-info"
        r = await self.helpers.request(url, headers=self.headers)
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
                await self.emit_event(hostname, "DNS_NAME", event, tags=tags)

    async def query(self, query):
        results = set()
        query_type = 0 if self.include_related else 1
        url = f"{self.base_url}/domain/search?q={self.helpers.quote(query)}&type={query_type}&page=" + "{page}"
        i = 0
        agen = self.helpers.api_page_iter(url, headers=self.headers)
        try:
            async for j in agen:
                r = list(self.parse_results(j))
                if r:
                    results.update(set(r))
                if not r or i >= (self.max_pages - 1):
                    break
                i += 1
        finally:
            agen.aclose()
        return results

    def parse_results(self, r):
        for entry in r.get("list", []):
            yield entry["name"]
