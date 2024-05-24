from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class fullhunt(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the fullhunt.io API for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "FullHunt API Key"}

    base_url = "https://fullhunt.io/api/v1"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"x-api-key": self.api_key}
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/auth/status"
        j = (await self.request_with_fail_count(url, headers=self.headers)).json()
        remaining = j["user_credits"]["remaining_credits"]
        assert remaining > 0, "No credits remaining"

    async def request_url(self, query):
        url = f"{self.base_url}/domain/{self.helpers.quote(query)}/subdomains"
        response = await self.request_with_fail_count(url, headers=self.headers)
        return response

    def parse_results(self, r, query):
        return r.json().get("hosts", [])
