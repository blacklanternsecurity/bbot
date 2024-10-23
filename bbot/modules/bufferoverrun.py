from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class BufferOverrun(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query BufferOverrun's TLS API for subdomains",
        "created_date": "2024-10-23",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": "", "commercial": False}
    options_desc = {"api_key": "BufferOverrun API key", "commercial": "Use commercial API"}

    base_url = "https://tls.bufferover.run/dns"
    commercial_base_url = "https://bufferover-run-tls.p.rapidapi.com/ipv4/dns"

    def prepare_api_request(self, url, kwargs):
        if "x-rapidapi-key" in kwargs["headers"]:
            kwargs["headers"]["x-rapidapi-host"] = "bufferover-run-tls.p.rapidapi.com"
        else:
            kwargs["headers"]["x-api-key"] = self.api_key
        return url, kwargs

    async def request_url(self, query, commercial=None):
        if commercial is None:
            commercial = self.options.get("commercial", False)
        _, domain = self.helpers.split_domain(query)
        url = f"{self.commercial_base_url if commercial else self.base_url}?q=.{domain}"
        return await self.api_request(url)

    def parse_results(self, r, query):
        j = r.json()
        subdomains_set = set()
        if isinstance(j, dict):
            results = j.get("Results", [])
            for result in results:
                parts = result.split(",")
                if len(parts) > 4:
                    subdomain = parts[4].strip()
                    if subdomain and subdomain.endswith(f".{query}"):
                        subdomains_set.add(subdomain)
            for subdomain in subdomains_set:
                yield subdomain
