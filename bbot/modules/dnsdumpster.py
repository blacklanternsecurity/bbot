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
        "auth_required": True,
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="DNSDumpster API key", sensitive=True, mandatory=True)
        max_pages: int = Field(10, description="Maximum result pages to request per domain")

    base_url = "https://api.dnsdumpster.com"

    # host records returned per page. free keys cap out at 50 and can't page at all;
    # paid keys get 200 and may request subsequent pages
    page_size = 200
    # the API permits one request every two seconds
    request_interval = 2
    # response keys whose entries carry a "host"
    record_keys = ("a", "cname", "mx", "ns")

    async def setup(self):
        self.max_pages = self.config.get("max_pages", 10)
        return await super().setup()

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["X-API-Key"] = self.api_key
        return url, kwargs

    async def query(self, query):
        results = set()
        for page in range(1, self.max_pages + 1):
            # page 1 is the bare URL; the API only accepts an explicit page number from 2 on
            url = f"{self.base_url}/domain/{query}"
            if page > 1:
                url = f"{url}?page={page}"
                await self.helpers.sleep(self.request_interval)
            r = await self.api_request(url)
            if r is None:
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
                break
            results.update(await self.parse_results(r, query))
            # a short page is the last one
            if self.record_count(data) < self.page_size:
                break
        return results

    def record_count(self, data):
        return sum(len(data.get(k) or []) for k in self.record_keys)

    async def parse_results(self, r, query):
        results = set()
        data = r.json()
        if not isinstance(data, dict):
            return results
        for key in self.record_keys:
            for record in data.get(key) or []:
                if isinstance(record, dict):
                    host = record.get("host")
                    if host:
                        results.add(host.lower())
        return results
