from .shodan_dns import shodan_dns


class securitytrails(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the SecurityTrails API for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "SecurityTrails API key"}

    base_url = "https://api.securitytrails.com/v1"

    def setup(self):
        self.limit = 100
        return super().setup()

    def ping(self):
        r = self.request_with_fail_count(f"{self.base_url}/ping?apikey={self.api_key}")
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    def request_url(self, query):
        url = f"{self.base_url}/domain/{query}/subdomains?apikey={self.api_key}"
        return self.request_with_fail_count(url)

    def parse_results(self, r, query):
        j = r.json()
        if isinstance(j, dict):
            for host in j.get("subdomains", []):
                yield f"{host}.{query}"
