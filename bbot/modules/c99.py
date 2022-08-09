from .shodan_dns import shodan_dns


class c99(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the C99 API for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "c99.nl API key"}

    base_url = "https://api.c99.nl"

    def ping(self):
        url = f"{self.base_url}/randomnumber?key={self.api_key}&between=1,100&json"
        response = self.helpers.request(url)
        assert response.json()["success"] == True

    def query(self, query):
        url = f"{self.base_url}/subdomainfinder?key={self.api_key}&domain={self.helpers.quote(query)}&json"
        results = self.helpers.request(url)
        try:
            json = results.json()
            if json:
                subdomains = json.get("subdomains", [])
                if subdomains:
                    for s in subdomains:
                        subdomain = s.get("subdomain", "")
                        if subdomain:
                            yield subdomain
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving c99.nl subdomains for {query}")
            self.debug(traceback.format_exc())
