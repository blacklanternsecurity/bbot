from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class leakix(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    options = {"api_key": ""}
    # NOTE: API key is not required (but having one will get you more results)
    options_desc = {"api_key": "LeakIX API Key"}
    meta = {
        "description": "Query leakix.net for subdomains",
        "created_date": "2022-07-11",
        "author": "@TheTechromancer",
    }

    base_url = "https://leakix.net"
    ping_url = f"{base_url}/host/1.2.3.4.5"

    async def setup(self):
        ret = await super(subdomain_enum_apikey, self).setup()
        self.headers = {"Accept": "application/json"}
        self.api_key = self.config.get("api_key", "")
        if self.api_key:
            self.headers["api-key"] = self.api_key
            return await self.require_api_key()
        return ret

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"]["api-key"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        url = f"{self.base_url}/api/subdomains/{self.helpers.quote(query)}"
        response = await self.api_request(url)
        return response

    def parse_results(self, r, query=None):
        json = r.json()
        if json:
            for entry in json:
                subdomain = entry.get("subdomain", "")
                if subdomain:
                    yield subdomain
