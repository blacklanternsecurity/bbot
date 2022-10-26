from bbot.modules.shodan_dns import shodan_dns


class bevigil(shodan_dns):
    """
    Retrieve OSINT data from mobile applications using BeVigil
    """
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Retrieve OSINT data from mobile applications using BeVigil", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {
        "api_key": "BeVigil OSINT API Key"
    }
    
    base_url = "https://osint.bevigil.com/api/{}/subdomains/"
    
    def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"X-Access-Token": self.api_key}
        return super().setup()

    def ping(self):
        pass

    def request_url(self, query):
        url = f"{self.base_url.format(self.helpers.quote(query))}"
        return self.helpers.request(url, headers=self.headers)

    def parse_results(self, r, query=None):
        results = set()
        subdomains = r.json().get("subdomains")
        if subdomains:
            results.update(subdomains)
        return results