from bbot.modules.shodan_dns import shodan_dns


class bevigil(shodan_dns):
    """
    Retrieve OSINT data from mobile applications using BeVigil
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Retrieve OSINT data from mobile applications using BeVigil", "auth_required": True}
    options = {"api_key": "", "urls": False}
    options_desc = {"api_key": "BeVigil OSINT API Key", "urls": "Emit URLs in addition to DNS_NAMEs"}

    base_url = "https://osint.bevigil.com/api"

    def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"X-Access-Token": self.api_key}
        self.urls = self.config.get("urls", False)
        return super().setup()

    def ping(self):
        pass

    def handle_event(self, event):
        query = self.make_query(event)
        subdomains = self.query(query, request_fn=self.request_subdomains, parse_fn=self.parse_subdomains)
        if subdomains:
            for subdomain in subdomains:
                self.emit_event(subdomain, "DNS_NAME", source=event)

        if self.urls:
            urls = self.query(query, request_fn=self.request_urls, parse_fn=self.parse_urls)
            if urls:
                for parsed_url in self.helpers.collapse_urls(urls):
                    self.emit_event(parsed_url.geturl(), "URL_UNVERIFIED", source=event)

    def request_subdomains(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}/subdomains/"
        return self.request_with_fail_count(url, headers=self.headers)

    def request_urls(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}/urls/"
        return self.request_with_fail_count(url, headers=self.headers)

    def parse_subdomains(self, r, query=None):
        results = set()
        subdomains = r.json().get("subdomains")
        if subdomains:
            results.update(subdomains)
        return results

    def parse_urls(self, r, query=None):
        results = set()
        urls = r.json().get("urls")
        if urls:
            results.update(urls)
        return results
