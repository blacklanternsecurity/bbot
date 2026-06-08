from bbot.modules.templates.shodan import shodan
from bbot.core.config.models import BaseModuleConfig, Field


class shodan_dns(shodan):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {"description": "Query Shodan for subdomains", "created_date": "2022-07-03", "author": "@TheTechromancer"}

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Shodan API key", sensitive=True, mandatory=True)

    base_url = "https://api.shodan.io"

    async def handle_event(self, event):
        await self.handle_event_paginated(event)

    def make_url(self, query):
        return f"{self.base_url}/dns/domain/{self.helpers.quote(query)}?key={{api_key}}&page={{page}}"

    async def parse_results(self, json, query):
        return [f"{sub}.{query}" for sub in json.get("subdomains", [])]
