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

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.headers = {"X-Access-Token": self.api_key}
        self.urls = self.config.get("urls", False)
        return await super().setup()

    async def ping(self):
        pass

    async def handle_event(self, event):
        query = self.make_query(event)
        subdomains = await self.query(query, request_fn=self.request_subdomains, parse_fn=self.parse_subdomains)
        if subdomains:
            for subdomain in subdomains:
                self.emit_event(subdomain, "DNS_NAME", source=event)

        if self.urls:
            urls = await self.query(query, request_fn=self.request_urls, parse_fn=self.parse_urls)
            if urls:
                for parsed_url in self.helpers.collapse_urls(urls):
                    self.emit_event(parsed_url.geturl(), "URL_UNVERIFIED", source=event)

    async def request_subdomains(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}/subdomains/"
        return await self.request_with_fail_count(url, headers=self.headers)

    async def request_urls(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}/urls/"
        return await self.request_with_fail_count(url, headers=self.headers)

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
