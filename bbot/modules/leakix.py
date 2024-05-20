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

    async def setup(self):
        ret = await super(subdomain_enum_apikey, self).setup()
        self.headers = {"Accept": "application/json"}
        self.api_key = self.config.get("api_key", "")
        if self.api_key:
            self.headers["api-key"] = self.api_key
            return await self.require_api_key()
        return ret

    async def ping(self):
        url = f"{self.base_url}/host/1.2.3.4.5"
        r = await self.helpers.request(url, headers=self.headers)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) != 401, resp_content

    async def request_url(self, query):
        url = f"{self.base_url}/api/subdomains/{self.helpers.quote(query)}"
        response = await self.request_with_fail_count(url, headers=self.headers)
        return response

    def parse_results(self, r, query=None):
        json = r.json()
        if json:
            for entry in json:
                subdomain = entry.get("subdomain", "")
                if subdomain:
                    yield subdomain
