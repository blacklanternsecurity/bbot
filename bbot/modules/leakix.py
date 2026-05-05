from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class leakix(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]

    class Config(BaseModuleConfig):
        api_key: str = Field("", description="LeakIX API Key", sensitive=True)

    # NOTE: API key is not required (but having one will get you more results)
    meta = {
        "description": "Query leakix.net for subdomains",
        "created_date": "2022-07-11",
        "author": "@TheTechromancer",
    }

    base_url = "https://leakix.net"
    ping_url = f"{base_url}/host/1.1.1.1"

    async def setup(self):
        ret = await super(subdomain_enum_apikey, self).setup()
        self.api_key = self.config.get("api_key", "")
        if self.api_key:
            return await self.require_api_key()
        return ret

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"]["api-key"] = self.api_key
            kwargs["headers"]["Accept"] = "application/json"
        return url, kwargs

    async def request_url(self, query):
        url = f"{self.base_url}/api/subdomains/{self.helpers.quote(query)}"
        response = await self.api_request(url)
        return response

    async def parse_results(self, r, query=None):
        results = set()
        json = r.json()
        if json:
            for entry in json:
                subdomain = entry.get("subdomain", "")
                if subdomain:
                    results.add(subdomain)
        return results
