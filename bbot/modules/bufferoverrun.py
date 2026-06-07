from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class BufferOverrun(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query BufferOverrun's TLS API for subdomains",
        "created_date": "2024-10-23",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="BufferOverrun API key", sensitive=True, mandatory=True)
        commercial: bool = Field(False, description="Use commercial API")

    base_url = "https://tls.bufferover.run/dns"
    commercial_base_url = "https://bufferover-run-tls.p.rapidapi.com/ipv4/dns"

    async def setup(self):
        self.commercial = self.config.get("commercial", False)
        return await super().setup()

    def prepare_api_request(self, url, kwargs):
        if self.commercial:
            kwargs["headers"]["x-rapidapi-host"] = "bufferover-run-tls.p.rapidapi.com"
            kwargs["headers"]["x-rapidapi-key"] = self.api_key
        else:
            kwargs["headers"]["x-api-key"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        url = f"{self.commercial_base_url if self.commercial else self.base_url}?q=.{query}"
        return await self.api_request(url)

    async def parse_results(self, r, query):
        j = r.json()
        subdomains_set = set()
        if isinstance(j, dict):
            results = j.get("Results", [])
            for result in results:
                parts = result.split(",")
                if len(parts) > 4:
                    subdomain = parts[4].strip()
                    if subdomain and subdomain.endswith(f".{query}"):
                        subdomains_set.add(subdomain)
        return subdomains_set
