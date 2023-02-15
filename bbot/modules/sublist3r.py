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
        return self.request_with_fail_count(f"{self.base_url}?domain={query}", timeout=self.http_timeout + 10)
