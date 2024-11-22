from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class virustotal(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query VirusTotal's API for subdomains",
        "created_date": "2022-08-25",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "VirusTotal API Key"}

    base_url = "https://www.virustotal.com/api/v3"
    api_page_iter_kwargs = {"json": False, "next_key": lambda r: r.json().get("links", {}).get("next", "")}

    def make_url(self, query):
        return f"{self.base_url}/domains/{self.helpers.quote(query)}/subdomains"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-apikey"] = self.api_key
        return url, kwargs

    async def parse_results(self, r, query):
        text = getattr(r, "text", "")
        return await self.scan.extract_in_scope_hostnames(text)
