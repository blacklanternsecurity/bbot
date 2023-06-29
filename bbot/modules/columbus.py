from .crobat import crobat


class columbus(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query the Columbus Project API for subdomains"}
    options = {"limit": 500}
    options_desc = {"limit": "Max number of subdomains to retrieve"}

    base_url = "https://columbus.elmasy.com/api/lookup"

    async def setup(self):
        self.limit = self.config.get("limit", 500)
        return await super().setup()

    async def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}"
        return await self.request_with_fail_count(url)

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json and isinstance(json, list):
            return set([f"{s.lower()}.{query}" for s in json[: self.limit]])
        return results
