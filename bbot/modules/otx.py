from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class otx(subdomain_enum_apikey):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query otx.alienvault.com for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "OTX API key"}

    base_url = "https://otx.alienvault.com"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["X-OTX-API-KEY"] = self.api_key
        return url, kwargs

    def request_url(self, query):
        url = f"{self.base_url}/api/v1/indicators/domain/{self.helpers.quote(query)}/passive_dns"
        return self.api_request(url)

    async def parse_results(self, r, query):
        results = set()
        j = r.json()
        if isinstance(j, dict):
            for entry in j.get("passive_dns", []):
                subdomain = entry.get("hostname", "")
                if subdomain:
                    results.add(subdomain)
        return results
