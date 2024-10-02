from bbot.modules.templates.subdomain_enum import subdomain_enum


class otx(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query otx.alienvault.com for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
    }

    base_url = "https://otx.alienvault.com"

    def request_url(self, query):
        url = f"{self.base_url}/api/v1/indicators/domain/{self.helpers.quote(query)}/passive_dns"
        return self.api_request(url)

    def parse_results(self, r, query):
        j = r.json()
        if isinstance(j, dict):
            for entry in j.get("passive_dns", []):
                subdomain = entry.get("hostname", "")
                if subdomain:
                    yield subdomain
