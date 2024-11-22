from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class chaos(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query ProjectDiscovery's Chaos API for subdomains",
        "created_date": "2022-08-14",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Chaos API key"}

    base_url = "https://dns.projectdiscovery.io/dns"
    ping_url = f"{base_url}/example.com"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        _, domain = self.helpers.split_domain(query)
        url = f"{self.base_url}/{domain}/subdomains"
        return await self.api_request(url)

    async def parse_results(self, r, query):
        results = set()
        j = r.json()
        subdomains_set = set()
        if isinstance(j, dict):
            domain = j.get("domain", "")
            if domain:
                subdomains = j.get("subdomains", [])
                for s in subdomains:
                    s = s.lower().strip(".*")
                    subdomains_set.add(s)
                for s in subdomains_set:
                    full_subdomain = f"{s}.{domain}"
                    if full_subdomain and full_subdomain.endswith(f".{query}"):
                        results.add(full_subdomain)
        return results
