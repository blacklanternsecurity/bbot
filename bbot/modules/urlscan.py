from urllib.parse import quote

from .crobat import crobat


class urlscan(crobat):
    flags = ["subdomain-enum"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL"]

    def handle_event(self, event):
        if "target" in event.tags:
            query = str(event.data).lower()
        else:
            query = self.helpers.parent_domain(event.data).lower()

        if query not in self.processed:
            self.processed.add(hash(query))

            for domain, url in self.query(query):
                source_event = event
                if domain:
                    domain_event = self.scan.make_event(domain, "DNS_NAME", source=event)
                    if str(domain_event.host).endswith(query) and not str(domain_event.host) == str(event.host):
                        self.emit_event(domain_event)
                        source_event = domain_event
                if url:
                    url_event = self.scan.make_event(url, "URL", source=source_event)
                    if str(url_event.host).endswith(query):
                        self.emit_event(url_event)
                    else:
                        self.debug(f"{url_event.host} does not match {query}")

    def query(self, query):
        results = self.helpers.request(f"https://urlscan.io/api/v1/search/?q={quote(query)}")
        try:
            json = results.json()
            if json and type(json) == dict:
                for result in json.get("results", []):
                    if result and type(result) == dict:
                        task = result.get("task", {})
                        if task and type(task) == dict:
                            domain = task.get("domain", "")
                            url = task.get("url", "")
                            if domain or url:
                                yield domain, url
                        page = result.get("page", {})
                        if page and type(page) == dict:
                            domain = page.get("domain", "")
                            url = page.get("url", "")
                            if domain or url:
                                yield domain, url
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving urlscan results")
            self.debug(traceback.format_exc())
