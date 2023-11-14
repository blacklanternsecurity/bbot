from bbot.modules.shodan_dns import shodan_dns


class virustotal(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query VirusTotal's API for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "VirusTotal API Key"}

    base_url = "https://www.virustotal.com/api/v3"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"x-apikey": self.api_key}
        return await super().setup()

    async def ping(self):
        # virustotal does not have a ping function
        return

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
        agen = self.helpers.api_page_iter(
            url, json=False, headers=self.headers, next_key=lambda r: r.json().get("links", {}).get("next", "")
        )
        try:
            async for response in agen:
                if r := self.parse_results(response, query):
                    results.update(r)
                else:
                    break
        finally:
            agen.aclose()
        return results
