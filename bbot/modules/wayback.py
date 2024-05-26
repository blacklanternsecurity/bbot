from datetime import datetime

from bbot.modules.templates.subdomain_enum import subdomain_enum


class wayback(subdomain_enum):
    flags = ["passive", "subdomain-enum", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED", "DNS_NAME"]
    meta = {
        "description": "Query archive.org's API for subdomains",
        "created_date": "2022-04-01",
        "author": "@pmueller",
    }
    options = {"urls": False, "garbage_threshold": 10}
    options_desc = {
        "urls": "emit URLs in addition to DNS_NAMEs",
        "garbage_threshold": "Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)",
    }
    in_scope_only = True

    base_url = "http://web.archive.org"

    async def setup(self):
        self.urls = self.config.get("urls", False)
        self.garbage_threshold = self.config.get("garbage_threshold", 10)
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        for result, event_type in await self.query(query):
            await self.emit_event(
                result,
                event_type,
                event,
                abort_if=self.abort_if,
                context=f'{{module}} queried archive.org for "{query}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, query):
        results = set()
        waybackurl = f"{self.base_url}/cdx/search/cdx?url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        r = await self.helpers.request(waybackurl, timeout=self.http_timeout + 10)
        if not r:
            self.warning(f'Error connecting to archive.org for query "{query}"')
            return results
        try:
            j = r.json()
            assert type(j) == list
        except Exception:
            self.warning(f'Error JSON-decoding archive.org response for query "{query}"')
            return results

        urls = []
        for result in j[1:]:
            try:
                url = result[0]
                urls.append(url)
            except KeyError:
                continue

        self.verbose(f"Found {len(urls):,} URLs for {query}")

        dns_names = set()
        collapsed_urls = 0
        start_time = datetime.now()
        # we consolidate URLs to cut down on garbage data
        # this is CPU-intensive, so we do it in its own core.
        parsed_urls = await self.helpers.run_in_executor_mp(
            self.helpers.validators.collapse_urls,
            urls,
            threshold=self.garbage_threshold,
        )
        for parsed_url in parsed_urls:
            collapsed_urls += 1
            if not self.urls:
                dns_name = parsed_url.hostname
                h = hash(dns_name)
                if h not in dns_names:
                    dns_names.add(h)
                    results.add((dns_name, "DNS_NAME"))
            else:
                results.add((parsed_url.geturl(), "URL_UNVERIFIED"))
        end_time = datetime.now()
        duration = self.helpers.human_timedelta(end_time - start_time)
        self.verbose(f"Collapsed {len(urls):,} -> {collapsed_urls:,} URLs in {duration}")
        return results
