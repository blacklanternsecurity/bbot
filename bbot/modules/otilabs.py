from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class otilabs(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query the OTI Labs Domain Intelligence API for subdomains",
        "created_date": "2026-10-05",
        "author": "@OsirisTechnicalInstitute",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field(
            "",
            description="RapidAPI key subscribed to the OTI Labs Domain Intelligence API",
            sensitive=True,
            mandatory=True,
        )

    base_url = "https://domain-intelligence-api.p.rapidapi.com"
    api_host = "domain-intelligence-api.p.rapidapi.com"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-rapidapi-host"] = self.api_host
        kwargs["headers"]["x-rapidapi-key"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        # BBOT queries each domain once, so ask the API to wait for all of its sources (wait=1)
        # instead of returning its fast partial snapshot. That takes 15-20 seconds for a domain
        # the API hasn't seen before and is immediate when it's cached.
        url = f"{self.base_url}/domain/{self.helpers.quote(query)}/subdomains?wait=1"
        return await self.api_request(url, timeout=self.http_timeout_infrastructure + 20)

    async def parse_results(self, r, query):
        results = set()
        j = r.json()
        if isinstance(j, dict):
            for host in j.get("subdomains", []):
                if isinstance(host, str) and host.endswith(f".{query}"):
                    results.add(host)
        return results
