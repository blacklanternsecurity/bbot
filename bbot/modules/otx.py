from .crobat import crobat


class otx(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query otx.alienvault.com for subdomains"}

    base_url = "https://otx.alienvault.com"

    def request_url(self, query):
        url = f"{self.base_url}/api/v1/indicators/domain/{self.helpers.quote(query)}/passive_dns"
        return self.request_with_fail_count(url)

    def parse_results(self, r, query):
        j = r.json()
        if isinstance(j, dict):
            for entry in j.get("passive_dns", []):
                subdomain = entry.get("hostname", "")
                if subdomain:
                    yield subdomain
