from .crobat import crobat


class leakix(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query leakix.net for subdomains"}

    base_url = "https://leakix.net"

    def request_url(self, query):
        url = f"{self.base_url}/api/subdomains/{self.helpers.quote(query)}"
        return self.request_with_fail_count(url, headers={"Accept": "application/json"})

    def parse_results(self, r, query=None):
        json = r.json()
        if json:
            for entry in json:
                subdomain = entry.get("subdomain", "")
                if subdomain:
                    yield subdomain
