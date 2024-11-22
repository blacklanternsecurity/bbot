from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class passivetotal(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the PassiveTotal API for subdomains",
        "created_date": "2022-08-08",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "PassiveTotal API Key in the format of 'username:api_key'"}

    base_url = "https://api.passivetotal.org/v2"

    async def setup(self):
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/account/quota"
        j = (await self.api_request(url)).json()
        limit = j["user"]["limits"]["search_api"]
        used = j["user"]["counts"]["search_api"]
        assert used < limit, "No quota remaining"

    def prepare_api_request(self, url, kwargs):
        api_username, api_key = self.api_key.split(":", 1)
        kwargs["auth"] = (api_username, api_key)
        return url, kwargs

    async def abort_if(self, event):
        # RiskIQ is famous for their junk data
        return await super().abort_if(event) or "unresolved" in event.tags

    async def request_url(self, query):
        url = f"{self.base_url}/enrichment/subdomains?query={self.helpers.quote(query)}"
        return await self.api_request(url)

    async def parse_results(self, r, query):
        results = set()
        for subdomain in r.json().get("subdomains", []):
            results.add(f"{subdomain}.{query}")
        return results
