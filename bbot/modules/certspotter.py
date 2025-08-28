from bbot.modules.templates.subdomain_enum import subdomain_enum


class certspotter(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Certspotter's API for subdomains",
        "created_date": "2022-07-28",
        "author": "@TheTechromancer",
    }

    base_url = "https://api.certspotter.com/v1"

    def request_url(self, query):
        url = f"{self.base_url}/issuances?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
        return self.api_request(url)

    async def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json:
            for r in json:
                for dns_name in r.get("dns_names", []):
                    results.add(dns_name.lstrip(".*").rstrip("."))
        return results
