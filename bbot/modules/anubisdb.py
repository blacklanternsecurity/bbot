from .crobat import crobat


class anubisdb(crobat):

    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query jldc.me's database for subdomains"}

    base_url = "https://jldc.me/anubis/subdomains"

    def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}"
        return self.helpers.request(url)

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json:
            for hostname in json:
                hostname = str(hostname).lower()
                if hostname.endswith(f".{query}"):
                    results.add(hostname)
        return results
