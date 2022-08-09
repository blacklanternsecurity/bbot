from bbot.modules.crobat import crobat


class certspotter(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query Certspotter's API for subdomains"}

    base_url = "https://api.certspotter.com/v1"

    def request_url(self, query):
        url = f"{self.base_url}/issuances?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
        return self.helpers.request(url)

    def parse_results(self, r, query):
        json = r.json()
        if json:
            for r in json:
                for dns_name in r.get("dns_names", []):
                    yield dns_name.lstrip(".*").rstrip(".")
