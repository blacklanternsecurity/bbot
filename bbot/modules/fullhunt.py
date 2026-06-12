from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class fullhunt(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query the fullhunt.io API for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="FullHunt API Key", sensitive=True, mandatory=True)

    base_url = "https://fullhunt.io/api/v1"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/auth/status"
        j = (await self.api_request(url, retry_on_http_429=False)).json()
        remaining = j["user_credits"]["remaining_credits"]
        assert remaining > 0, "No credits remaining"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-api-key"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        url = f"{self.base_url}/domain/{self.helpers.quote(query)}/subdomains"
        response = await self.api_request(url)
        return response

    async def parse_results(self, r, query):
        return r.json().get("hosts", [])
