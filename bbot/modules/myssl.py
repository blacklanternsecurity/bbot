from bbot.modules.templates.subdomain_enum import subdomain_enum


class myssl(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query myssl.com's API for subdomains",
        "created_date": "2023-07-10",
        "author": "@TheTechromancer",
    }

    base_url = "https://myssl.com/api/v1/discover_sub_domain"

    async def request_url(self, query):
        url = f"{self.base_url}?domain={self.helpers.quote(query)}"
        return await self.api_request(url)

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json and isinstance(json, dict):
            data = json.get("data", [])
            for d in data:
                hostname = d.get("domain", "").lower()
                if hostname:
                    results.add(hostname)
        return results
