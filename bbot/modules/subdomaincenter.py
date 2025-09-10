from bbot.modules.templates.subdomain_enum import subdomain_enum


class subdomaincenter(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query subdomain.center's API for subdomains",
        "created_date": "2023-07-26",
        "author": "@TheTechromancer",
    }

    base_url = "https://api.subdomain.center"

    async def request_url(self, query):
        url = f"{self.base_url}/?domain={self.helpers.quote(query)}"
        response = await self.api_request(url)
        return response

    async def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json and isinstance(json, list):
            results = set(json)
        return results
