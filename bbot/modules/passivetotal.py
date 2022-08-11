from bbot.modules.shodan_dns import shodan_dns


class passivetotal(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the PassiveTotal API for subdomains", "auth_required": True}
    options = {"username": "", "api_key": ""}
    options_desc = {"username": "RiskIQ Username", "api_key": "RiskIQ API Key"}

    base_url = "https://api.passivetotal.org/v2"

    def setup(self):
        self.username = self.config.get("username", "")
        self.api_key = self.config.get("api_key", "")
        self.auth = (self.username, self.api_key)
        return super().setup()

    def ping(self):
        url = f"{self.base_url}/account/quota"
        j = self.helpers.request(url, auth=self.auth).json()
        limit = j["user"]["limits"]["search_api"]
        used = j["user"]["counts"]["search_api"]
        assert used < limit, "No quota remaining"

    def abort_if(self, event):
        # RiskIQ is famous for their junk data
        return super().abort_if(event) or "unresolved" in event.tags

    def query(self, query):
        url = f"{self.base_url}/enrichment/subdomains?query={self.helpers.quote(query)}"
        j = self.helpers.request(url, auth=self.auth).json()
        for subdomain in j.get("subdomains", []):
            yield f"{subdomain}.{query}"

    @property
    def api_secret(self):
        return self.username and self.api_key
