from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class shodan_dns(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query Shodan for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}

    base_url = "https://api.shodan.io"

    async def ping(self):
        url = f"{self.base_url}/api-info?key={self.api_key}"
        r = await self.request_with_fail_count(url)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    async def request_url(self, query):
        url = f"{self.base_url}/dns/domain/{self.helpers.quote(query)}?key={self.api_key}"
        response = await self.request_with_fail_count(url)
        return response

    def parse_results(self, r, query):
        json = r.json()
        if json:
            for hostname in json.get("subdomains", []):
                yield f"{hostname}.{query}"
