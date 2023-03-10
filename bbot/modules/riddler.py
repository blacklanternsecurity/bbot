from .crobat import crobat


class riddler(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query riddler.io for subdomains"}

    base_url = "https://riddler.io"

    def request_url(self, query):
        url = f"{self.base_url}/search/exportcsv?q=pld:{self.helpers.quote(query)}"
        return self.request_with_fail_count(url)

    def parse_results(self, r, query):
        results = set()
        text = getattr(r, "text", "")
        for match in self.helpers.regexes.dns_name_regex.findall(text):
            match = match.lower()
            if match.endswith(query):
                results.add(match)
        return results
