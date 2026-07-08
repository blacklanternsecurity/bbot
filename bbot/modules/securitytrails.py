from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class securitytrails(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query the SecurityTrails API for subdomains",
        "created_date": "2022-07-03",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="SecurityTrails API key", sensitive=True, mandatory=True)

    base_url = "https://api.securitytrails.com/v1"
    ping_url = f"{base_url}/ping?apikey={{api_key}}"

    async def setup(self):
        self.limit = 100
        return await super().setup()

    async def request_url(self, query):
        url = f"{self.base_url}/domain/{query}/subdomains?apikey={{api_key}}"
        response = await self.api_request(url)
        return response

    async def parse_results(self, r, query):
        results = set()
        j = r.json()
        if isinstance(j, dict):
            for host in j.get("subdomains", []):
                results.add(f"{host}.{query}")
        return results
