from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class Trickest(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Trickest's API for subdomains",
        "author": "@amiremami",
        "created_date": "2024-07-27",
        "auth_required": True,
    }
    options = {
        "api_key": "",
    }
    options_desc = {
        "api_key": "Trickest API key",
    }

    base_url = "https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be"
    ping_url = f"{base_url}/dataset"
    dataset_id = "a0a49ca9-03bb-45e0-aa9a-ad59082ebdfc"
    page_size = 50

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = f"Token {self.api_key}"
        return url, kwargs

    async def handle_event(self, event):
        await self.handle_event_paginated(event)

    def make_url(self, query):
        url = f"{self.base_url}/view?q=hostname%20~%20%22.{self.helpers.quote(query)}%22"
        url += f"&dataset_id={self.dataset_id}"
        url += "&limit={page_size}&offset={offset}&select=hostname&orderby=hostname"
        return url

    def parse_results(self, j, query):
        results = j.get("results", [])
        subdomains = set()
        for item in results:
            hostname = item.get("hostname", "")
            if hostname:
                subdomains.add(hostname)
        return subdomains
