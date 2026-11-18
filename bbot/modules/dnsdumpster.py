from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class dnsdumpster(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "description": "Query dnsdumpster for subdomains",
        "created_date": "2022-03-12",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="DNSDumpster API key", sensitive=True, mandatory=True)
        max_pages: int = Field(10, description="Maximum result pages to request per domain")

    base_url = "https://api.dnsdumpster.com"

    async def setup(self):
        self.max_pages = self.config.get("max_pages", 10)
        return await super().setup()

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["X-API-Key"] = self.api_key
        return url, kwargs

    async def query(self, query):
        results = set()
        a_records = 0
        for page in range(1, self.max_pages + 1):
            # page 1 is the bare URL; the API only accepts an explicit page number from 2 on
            url = f"{self.base_url}/domain/{query}"
            if page > 1:
                url = f"{url}?page={page}"
            r = await self.api_request(url)
            if r is None:
                self.verbose(f'No response for "{query}" (page {page})')
                break
            if page > 1 and r.status_code in (401, 403):
                self.verbose(f"Paging past the first page requires a paid membership (HTTP {r.status_code})")
                break
            try:
                data = r.json()
            except Exception:
                self.verbose(f'Error parsing JSON for "{query}" (HTTP {r.status_code})')
                break
            if not isinstance(data, dict):
                self.verbose(f'Unexpected response for "{query}" (HTTP {r.status_code}): {r.text[:200]}')
                break
            results.update(await self.scan.extract_in_scope_hostnames(r.text))
            # the response reports how many A records exist in total; stop once they have all been seen
            page_a_records = len(data.get("a") or [])
            a_records += page_a_records
            total = data.get("total_a_recs")
            if not isinstance(total, int) or not page_a_records or a_records >= total:
                break
        return results
