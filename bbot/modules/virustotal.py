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

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-apikey"] = self.api_key
        return url, kwargs

    def parse_results(self, r, query):
        results = set()
        text = getattr(r, "text", "")
        for match in self.helpers.regexes.dns_name_regex.findall(text):
            match = match.lower()
            if match.endswith(query):
                results.add(match)
        return results

    async def query(self, query):
        results = set()
        url = f"{self.base_url}/domains/{self.helpers.quote(query)}/subdomains"
        agen = self.api_page_iter(url, json=False, next_key=lambda r: r.json().get("links", {}).get("next", ""))
        try:
            async for response in agen:
                r = self.parse_results(response, query)
                if not r:
                    break
                results.update(r)
        finally:
            agen.aclose()
        return results
