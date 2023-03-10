from bbot.modules.shodan_dns import shodan_dns


class virustotal(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query VirusTotal's API for subdomains", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "VirusTotal API Key"}

    base_url = "https://www.virustotal.com/api/v3"

    def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"x-apikey": self.api_key}
        return super().setup()

    def ping(self):
        # virustotal does not have a ping function
        return

    def request_url(self, query):
        url = f"{self.base_url}/domains/{self.helpers.quote(query)}/subdomains"
        return self.request_with_fail_count(url, headers=self.headers)

    def parse_results(self, r, query):
        results = set()
        text = getattr(r, "text", "")
        for match in self.helpers.regexes.dns_name_regex.findall(text):
            match = match.lower()
            if match.endswith(query):
                results.add(match)
        return results
