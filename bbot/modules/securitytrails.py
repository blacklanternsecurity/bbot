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
        r = self.helpers.request(f"{self.base_url}/ping?apikey={self.api_key}")
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    def query(self, query):
        url = f"{self.base_url}/domain/{query}/subdomains?apikey={self.api_key}"
        r = self.helpers.request(url)
        try:
            j = r.json()
            if type(j) == dict:
                for host in j.get("subdomains", []):
                    yield f"{host}.{query}"
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f'Error retrieving subdomains for "{query}"')
            self.debug(traceback.format_exc())
