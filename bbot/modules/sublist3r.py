from bbot.modules.templates.subdomain_enum import subdomain_enum


class sublist3r(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    # tag "subdomain-enum" removed 2023-02-24 because API is offline
    flags = ["passive", "safe"]
    meta = {
        "description": "Query sublist3r's API for subdomains",
    }

    base_url = "https://api.sublist3r.com/search.php"

    def request_url(self, query):
        return self.request_with_fail_count(f"{self.base_url}?domain={query}", timeout=self.http_timeout + 10)
