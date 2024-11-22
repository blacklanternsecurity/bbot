from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class bevigil(subdomain_enum_apikey):
    """
    Retrieve OSINT data from mobile applications using BeVigil
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Retrieve OSINT data from mobile applications using BeVigil",
        "created_date": "2022-10-26",
        "author": "@alt-glitch",
        "auth_required": True,
    }
    options = {"api_key": "", "urls": False}
    options_desc = {"api_key": "BeVigil OSINT API Key", "urls": "Emit URLs in addition to DNS_NAMEs"}

    base_url = "https://osint.bevigil.com/api"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        self.urls = self.config.get("urls", False)
        return await super().setup()

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["X-Access-Token"] = self.api_key
        return url, kwargs

    async def handle_event(self, event):
        query = self.make_query(event)
        subdomains = await self.query(query, request_fn=self.request_subdomains, parse_fn=self.parse_subdomains)
        if subdomains:
            for subdomain in subdomains:
                await self.emit_event(
                    subdomain,
                    "DNS_NAME",
                    parent=event,
                    context=f'{{module}} queried BeVigil\'s API for "{query}" and discovered {{event.type}}: {{event.data}}',
                )

        if self.urls:
            urls = await self.query(query, request_fn=self.request_urls, parse_fn=self.parse_urls)
            if urls:
                for parsed_url in await self.helpers.run_in_executor_mp(self.helpers.validators.collapse_urls, urls):
                    await self.emit_event(
                        parsed_url.geturl(),
                        "URL_UNVERIFIED",
                        parent=event,
                        context=f'{{module}} queried BeVigil\'s API for "{query}" and discovered {{event.type}}: {{event.data}}',
                    )

    async def request_subdomains(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}/subdomains/"
        return await self.api_request(url)

    async def request_urls(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}/urls/"
        return await self.api_request(url)

    async def parse_subdomains(self, r, query=None):
        results = set()
        subdomains = r.json().get("subdomains")
        if subdomains:
            results.update(subdomains)
        return results

    async def parse_urls(self, r, query=None):
        results = set()
        urls = r.json().get("urls")
        if urls:
            results.update(urls)
        return results
