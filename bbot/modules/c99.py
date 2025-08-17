from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class c99(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the C99 API for subdomains",
        "created_date": "2022-07-08",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "c99.nl API key"}

    base_url = "https://api.c99.nl"
    ping_url = f"{base_url}/randomnumber?key={{api_key}}&between=1,100&json"

    async def ping(self):
        url = f"{self.base_url}/randomnumber?key={{api_key}}&between=1,100&json"
        response = await self.api_request(url, retry_on_http_429=False)
        assert response.json()["success"] is True, getattr(response, "text", "no response from server")

    async def request_url(self, query):
        url = f"{self.base_url}/subdomainfinder?key={{api_key}}&domain={self.helpers.quote(query)}&json"
        return await self.api_request(url)

    async def parse_results(self, r, query):
        results = set()
        j = r.json()
        if isinstance(j, dict):
            subdomains = j.get("subdomains", [])
            if subdomains:
                for s in subdomains:
                    subdomain = s.get("subdomain", "")
                    if subdomain:
                        results.add(subdomain)
        return results
