from .crobat import crobat


class shodan_dns(crobat):
    """
    A typical module for authenticated, API-based subdomain enumeration
    Inherited by several other modules including securitytrails, c99.nl, etc.
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    options = {"api_key": ""}
    options_desc = {"api_key": "Shodan API key"}
    flags = ["subdomain-enum", "passive"]

    base_url = "https://api.shodan.io"

    def setup(self):
        super().setup()
        self.api_key = self.config.get("api_key", "")
        if self.api_key:
            try:
                self.ping()
                return True
            except Exception as e:
                self.warning(f"Error contacting API")
                e = str(e).strip()
                if e:
                    self.verbose(e)
        else:
            self.warning("No API key set")
        return False

    def ping(self):
        r = self.helpers.request(f"https://api.shodan.io/api-info?key={self.api_key}")
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    def query(self, query):
        url = f"{self.base_url}/dns/domain/{self.helpers.quote(query)}?key={self.api_key}"
        results = self.helpers.request(url)
        try:
            json = results.json()
            if json:
                for hostname in json.get("subdomains"):
                    yield f"{hostname}.{query}"
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving shodan subdomains for {query}")
            self.debug(traceback.format_exc())
