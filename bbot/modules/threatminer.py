from bbot.modules.templates.subdomain_enum import subdomain_enum


class threatminer(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query threatminer's API for subdomains",
    }

    base_url = "https://api.threatminer.org/v2"

    async def request_url(self, query):
        url = f"{self.base_url}/domain.php?q={self.helpers.quote(query)}&rt=5"
        r = await self.request_with_fail_count(url, timeout=self.http_timeout + 30)
        return r

    def parse_results(self, r, query):
        j = r.json()
        return list(j.get("results", []))
