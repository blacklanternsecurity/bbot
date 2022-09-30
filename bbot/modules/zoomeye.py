from bbot.modules.shodan_dns import shodan_dns


class zoomeye(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "passive", "safe"]
    meta = {"description": "Query ZoomEye's API for subdomains", "auth_required": True}
    options = {"api_key": "", "max_pages": 20, "include_related": False}
    options_desc = {
        "api_key": "ZoomEye API key",
        "max_pages": "How many pages of results to fetch",
        "include_related": "Include domains which may be related to the target",
    }

    base_url = "https://api.zoomeye.org"

    def setup(self):
        self.max_pages = self.config.get("max_pages", 20)
        self.headers = {"API-KEY": self.config.get("api_key", "")}
        self.include_related = self.config.get("include_related", False)
        return super().setup()

    def ping(self):
        r = self.helpers.request(f"{self.base_url}/resources-info", headers=self.headers)
        assert int(r.json()["quota_info"]["remain_total_quota"]) > 0, "No quota remaining"

    def handle_event(self, event):
        query = self.make_query(event)
        results = self.query(query)
        if results:
            for hostname in results:
                if hostname == event:
                    continue
                tags = []
                if not hostname.endswith(f".{query}"):
                    tags = ["affiliate"]
                self.emit_event(hostname, "DNS_NAME", event, tags=tags)

    def query(self, query):
        query_type = 0 if self.include_related else 1
        url = f"{self.base_url}/domain/search?q={self.helpers.quote(query)}&type={query_type}&page=" + "{page}"
        for i, j in enumerate(self.helpers.api_page_iter(url, headers=self.headers)):
            results = list(self.parse_results(j))
            if results:
                yield from results
            if not results or i >= (self.max_pages - 1) or self.scan.stopping:
                break

    def parse_results(self, r):
        for entry in r.get("list", []):
            yield entry["name"]
