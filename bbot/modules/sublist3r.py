from .crobat import crobat


class sublist3r(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query sublist3r's API for subdomains",
    }

    base_url = "https://api.sublist3r.com/search.php"

    def request_url(self, query):
        return self.helpers.request(f"{self.base_url}?domain={query}")

    def parse_results(self, r, query):
        json = r.json()
        if json:
            for hostname in json:
                yield hostname
