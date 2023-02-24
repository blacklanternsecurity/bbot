from bbot.modules.crobat import crobat


class hackertarget(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the hackertarget.com API for subdomains"}

    base_url = "https://api.hackertarget.com"

    def request_url(self, query):
        return self.request_with_fail_count(f"{self.base_url}/hostsearch/?q={self.helpers.quote(query)}")

    def parse_results(self, r, query):
        for line in r.text.splitlines():
            host = line.split(",")[0]
            if self.helpers.validators.validate_host(host):
                yield host
