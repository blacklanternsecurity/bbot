from bbot.modules.shodan_dns import shodan_dns


class fullhunt(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the fullhunt.io API for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "FullHunt API Key"}

    base_url = "https://fullhunt.io/api/v1"

    def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"x-api-key": self.api_key}
        return super().setup()

    def ping(self):
        url = f"{self.base_url}/auth/status"
        j = self.request_with_fail_count(url, headers=self.headers).json()
        remaining = j["user_credits"]["remaining_credits"]
        assert remaining > 0, "No credits remaining"

    def request_url(self, query):
        url = f"{self.base_url}/domain/{self.helpers.quote(query)}/subdomains"
        return self.request_with_fail_count(url, headers=self.headers)

    def parse_results(self, r, query):
        return r.json().get("hosts", [])
