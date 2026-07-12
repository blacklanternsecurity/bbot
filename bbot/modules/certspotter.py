from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class certspotter(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query Certspotter's API for subdomains",
        "created_date": "2022-07-28",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str = Field(
            "", description="SSLMate API key (enables pagination and higher rate limits)", sensitive=True
        )

    base_url = "https://api.certspotter.com/v1"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        return await super().setup()

    def request_url(self, query):
        url = f"{self.base_url}/issuances?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
        return self.api_request(url)

    async def handle_event(self, event):
        if not self.api_key:
            return await super().handle_event(event)
        query = self.make_query(event)
        after = None
        while True:
            url = f"{self.base_url}/issuances?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
            if after is not None:
                url += f"&after={after}"
            response = await self.api_request(url)
            if response is None:
                break
            try:
                json_data = response.json()
            except Exception:
                break
            if not json_data or not isinstance(json_data, list):
                break
            for hostname in await self.parse_results(response, query):
                if hostname:
                    try:
                        hostname = self.helpers.validators.validate_host(hostname)
                    except ValueError:
                        continue
                    if hostname and hostname.endswith(f".{query}") and hostname != event.data:
                        await self.emit_event(
                            hostname,
                            "DNS_NAME",
                            event,
                            abort_if=self.abort_if,
                            context=f'{{module}} searched {self.source_pretty_name} for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                        )
            after = json_data[-1].get("id")
            if after is None:
                break

    async def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json and isinstance(json, list):
            for r in json:
                for dns_name in r.get("dns_names", []):
                    results.add(dns_name.lstrip(".*").rstrip("."))
        return results
