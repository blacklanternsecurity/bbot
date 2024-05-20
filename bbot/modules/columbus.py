from bbot.modules.templates.subdomain_enum import subdomain_enum


class columbus(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query the Columbus Project API for subdomains",
        "created_date": "2023-06-01",
        "author": "@TheTechromancer",
    }

    base_url = "https://columbus.elmasy.com/api/lookup"

    async def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}?days=365"
        return await self.request_with_fail_count(url)

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json and isinstance(json, list):
            return set([f"{s.lower()}.{query}" for s in json])
        return results
