from bbot.modules.templates.subdomain_enum import subdomain_enum


class subdomaincenter(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query subdomain.center's API for subdomains",
        "created_date": "2023-07-26",
        "author": "@TheTechromancer",
    }

    base_url = "https://api.subdomain.center"
    retries = 2

    async def sleep(self, time_to_wait):
        self.info(f"Sleeping for {time_to_wait} seconds to avoid rate limit")
        await self.helpers.sleep(time_to_wait)

    async def request_url(self, query):
        url = f"{self.base_url}/?domain={self.helpers.quote(query)}"
        response = None
        status_code = 0
        for i, _ in enumerate(range(self.retries + 1)):
            if i > 0:
                self.verbose(f"Retry #{i} for {query} after response code {status_code}")
            response = await self.helpers.request(url, timeout=self.http_timeout + 30)
            status_code = getattr(response, "status_code", 0)
            if status_code == 429:
                await self.sleep(20)
            else:
                break
        return response

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json and isinstance(json, list):
            results = set(json)
        return results
