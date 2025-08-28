from bbot.modules.templates.subdomain_enum import subdomain_enum
import asyncio


class pgp(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {
        "description": "Query common PGP servers and WKD endpoints for email addresses with caching",
        "created_date": "2022-08-10",
        "author": "@TheTechromancer",
    }

    options = {
        "search_urls": [
            "https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=vindex&search=<query>",
            "http://the.earth.li:11371/pks/lookup?fingerprint=on&op=vindex&search=<query>",
            "https://pgpkeys.eu/pks/lookup?search=<query>&op=index",
            "https://pgp.mit.edu/pks/lookup?search=<query>&op=index",
        ],
        "wkd_enabled": True,
        "max_concurrent_requests": 8,
    }
    options_desc = {
        "search_urls": "PGP key servers to search",
        "wkd_enabled": "Enable scanning /.well-known/openpgpkey/ WKD endpoints",
        "max_concurrent_requests": "Maximum concurrent requests to avoid rate-limits",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = {}  

    async def handle_event(self, event):
        query = self.make_query(event)

        # Check cache first, faster
        if query in self._cache:
            for email, keyserver in self._cache[query]:
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    event,
                    abort_if=self.abort_if,
                    context=f'{{module}} (cached) found email {email} from {keyserver} for "{query}"',
                )
            return

        tasks = []

        # keyserver URLs
        urls = self.config.get("search_urls", [])
        urls = [url.replace("<query>", self.helpers.quote(query)) for url in urls]

        # Add WKD URLs if enabled
        if self.config.get("wkd_enabled", True):
            urls.extend(
                [
                    f"https://{query}/.well-known/openpgpkey/hu/{query}",
                    f"http://{query}/.well-known/openpgpkey/hu/{query}",
                ]
            )

        semaphore = asyncio.Semaphore(self.config.get("max_concurrent_requests", 8))

        async def fetch(url):
            async with semaphore:
                try:
                    response = await self.helpers.request(url)
                    if not response:
                        return []
                    keyserver = self.helpers.urlparse(url).netloc
                    emails = await self.helpers.re.extract_emails(response.text)
                    return [(email.lower(), keyserver) for email in emails if email.lower().endswith(query)]
                except Exception:
                    self.debug(f"Failed fetching {url}")
                    return []

        # schedule fetches
        for url in urls:
            tasks.append(fetch(url))

        # Wait for all tasks
        results = await asyncio.gather(*tasks)

        # clean results, cache them, and emit
        combined_results = set()
        for batch in results:
            combined_results.update(batch)

        # Cache results
        self._cache[query] = combined_results

        for email, keyserver in combined_results:
            await self.emit_event(
                email,
                "EMAIL_ADDRESS",
                event,
                abort_if=self.abort_if,
                context=f'{{module}} queried PGP/WKD keyserver {keyserver} for "{query}" and found {{event.type}}: {{event.data}}',
            )
