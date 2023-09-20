from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class binaryedge(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the BinaryEdge API", "auth_required": True}
    options = {"api_key": "", "max_records": 1000}
    options_desc = {
        "api_key": "BinaryEdge API key",
        "max_records": "Limit results to help prevent exceeding API quota",
    }

    base_url = "https://api.binaryedge.io/v2"

    async def setup(self):
        self.max_records = self.config.get("max_records", 1000)
        self.headers = {"X-Key": self.config.get("api_key", "")}
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/user/subscription"
        j = (await self.request_with_fail_count(url, headers=self.headers)).json()
        assert j.get("requests_left", 0) > 0

    async def request_url(self, query):
        # todo: host query (certs + services)
        url = f"{self.base_url}/query/domains/subdomain/{self.helpers.quote(query)}"
        return await self.request_with_fail_count(url, headers=self.headers)

    def parse_results(self, r, query):
        j = r.json()
        return j.get("events", [])
