from bbot.modules.templates.subdomain_enum import subdomain_enum


class urlscan(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED"]
    meta = {
        "description": "Query urlscan.io for subdomains",
    }
    options = {"urls": False}
    options_desc = {"urls": "Emit URLs in addition to DNS_NAMEs"}

    base_url = "https://urlscan.io/api/v1"

    async def setup(self):
        self.urls = self.config.get("urls", False)
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        for domain, url in await self.query(query):
            source_event = event
            if domain and domain != query:
                domain_event = self.make_event(domain, "DNS_NAME", source=event)
                if domain_event:
                    if str(domain_event.host).endswith(query) and not str(domain_event.host) == str(event.host):
                        await self.emit_event(domain_event, abort_if=self.abort_if)
                        source_event = domain_event
            if url:
                url_event = self.make_event(url, "URL_UNVERIFIED", source=source_event)
                if url_event:
                    if str(url_event.host).endswith(query):
                        if self.urls:
                            await self.emit_event(url_event, abort_if=self.abort_if)
                        else:
                            await self.emit_event(
                                str(url_event.host), "DNS_NAME", source=event, abort_if=self.abort_if
                            )
                    else:
                        self.debug(f"{url_event.host} does not match {query}")

    async def query(self, query):
        results = set()
        url = f"{self.base_url}/search/?q={self.helpers.quote(query)}"
        r = await self.helpers.request(url)
        try:
            json = r.json()
            if json and type(json) == dict:
                for result in json.get("results", []):
                    if result and type(result) == dict:
                        task = result.get("task", {})
                        if task and type(task) == dict:
                            domain = task.get("domain", "")
                            url = task.get("url", "")
                            if domain or url:
                                results.add((domain, url))
                        page = result.get("page", {})
                        if page and type(page) == dict:
                            domain = page.get("domain", "")
                            url = page.get("url", "")
                            if domain or url:
                                results.add((domain, url))
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            self.verbose(f"Error retrieving urlscan results")
        return results
