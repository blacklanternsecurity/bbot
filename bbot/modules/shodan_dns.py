from bbot.modules.templates.shodan import shodan


class shodan_dns(shodan):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Shodan for subdomains",
        "created_date": "2022-07-03",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}

    base_url = "https://api.shodan.io"

    async def handle_event(self, event):
        await self.handle_event_paginated(event)

    def make_url(self, query):
        return f"{self.base_url}/dns/domain/{self.helpers.quote(query)}?key={{api_key}}&page={{page}}"

    def parse_results(self, json, query):
        return [f"{sub}.{query}" for sub in json.get("subdomains", [])]
