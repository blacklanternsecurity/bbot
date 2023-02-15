from .crobat import crobat


class rapiddns(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query rapiddns.io for subdomains"}

    base_url = "https://rapiddns.io"

    def request_url(self, query):
        url = f"{self.base_url}/subdomain/{self.helpers.quote(query)}?full=1#result"
        return self.request_with_fail_count(url)

    def parse_results(self, r, query):
        results = set()
        text = getattr(r, "text", "")
        for match in self.helpers.regexes.dns_name_regex.findall(text):
            match = match.lower()
            if match.endswith(query):
                results.add(match)
        return results
