from bbot.modules.crobat import crobat


class threatminer(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query threatminer's API for subdomains",
    }

    base_url = "https://api.threatminer.org/v2"

    def request_url(self, query):
        return self.request_with_fail_count(f"{self.base_url}/domain.php?q={self.helpers.quote(query)}&rt=5")

    def parse_results(self, r, query):
        j = r.json()
        yield from j.get("results", [])
