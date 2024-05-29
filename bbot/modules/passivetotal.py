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
    options = {"username": "", "api_key": ""}
    options_desc = {"username": "RiskIQ Username", "api_key": "RiskIQ API Key"}

    base_url = "https://api.passivetotal.org/v2"

    async def setup(self):
        self.username = self.config.get("username", "")
        self.api_key = self.config.get("api_key", "")
        self.auth = (self.username, self.api_key)
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/account/quota"
        j = (await self.request_with_fail_count(url, auth=self.auth)).json()
        limit = j["user"]["limits"]["search_api"]
        used = j["user"]["counts"]["search_api"]
        assert used < limit, "No quota remaining"

    async def abort_if(self, event):
        # RiskIQ is famous for their junk data
        return await super().abort_if(event) or "unresolved" in event.tags

    async def request_url(self, query):
        url = f"{self.base_url}/enrichment/subdomains?query={self.helpers.quote(query)}"
        return await self.request_with_fail_count(url, auth=self.auth)

    def parse_results(self, r, query):
        for subdomain in r.json().get("subdomains", []):
            yield f"{subdomain}.{query}"

    @property
    def auth_secret(self):
        return self.username and self.api_key
