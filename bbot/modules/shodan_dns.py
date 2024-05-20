from bbot.modules.templates.shodan import shodan


class shodan_dns(shodan):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query Shodan for subdomains",
        "created_date": "2022-07-03",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}

    base_url = "https://api.shodan.io"

    async def request_url(self, query):
        url = f"{self.base_url}/dns/domain/{self.helpers.quote(query)}?key={self.api_key}"
        response = await self.request_with_fail_count(url)
        return response

    def parse_results(self, r, query):
        json = r.json()
        if json:
            for hostname in json.get("subdomains", []):
                yield f"{hostname}.{query}"
