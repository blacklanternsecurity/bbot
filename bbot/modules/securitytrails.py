from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class securitytrails(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query the SecurityTrails API for subdomains",
        "created_date": "2022-07-03",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "SecurityTrails API key"}

    base_url = "https://api.securitytrails.com/v1"

    async def setup(self):
        self.limit = 100
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/ping?apikey={self.api_key}"
        r = await self.request_with_fail_count(url)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    async def request_url(self, query):
        url = f"{self.base_url}/domain/{query}/subdomains?apikey={self.api_key}"
        response = await self.request_with_fail_count(url)
        return response

    def parse_results(self, r, query):
        j = r.json()
        if isinstance(j, dict):
            for host in j.get("subdomains", []):
                yield f"{host}.{query}"
