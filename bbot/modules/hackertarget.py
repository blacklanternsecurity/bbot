from bbot.modules.templates.subdomain_enum import subdomain_enum


class hackertarget(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the hackertarget.com API for subdomains",
        "created_date": "2022-07-28",
        "author": "@TheTechromancer",
    }

    base_url = "https://api.hackertarget.com"

    async def request_url(self, query):
        url = f"{self.base_url}/hostsearch/?q={self.helpers.quote(query)}"
        response = await self.api_request(url)
        return response

    def parse_results(self, r, query):
        for line in r.text.splitlines():
            host = line.split(",")[0]
            try:
                self.helpers.validators.validate_host(host)
                yield host
            except ValueError:
                self.debug(f"Error validating API result: {line}")
                continue
