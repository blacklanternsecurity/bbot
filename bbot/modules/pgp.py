from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class pgp(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["safe", "passive", "email-enum"]
    meta = {
        "description": "Query common PGP servers for email addresses",
        "created_date": "2022-08-10",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        search_urls: list[str] = Field(
            [
                "https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=vindex&search=<query>",
                "http://the.earth.li:11371/pks/lookup?fingerprint=on&op=vindex&search=<query>",
                "https://pgpkeys.eu/pks/lookup?search=<query>&op=index",
                "https://pgp.mit.edu/pks/lookup?search=<query>&op=index",
            ],
            description="PGP key servers to search",
        )

    async def handle_event(self, event):
        query = self.make_query(event)
        results = await self.query(query)
        if results:
            for email, keyserver in results:
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    event,
                    abort_if=self.abort_if,
                    context=f'{{module}} queried PGP keyserver {keyserver} for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                )

    async def query(self, query):
        results = set()
        urls = self.config.get("search_urls", [])
        urls = [url.replace("<query>", self.helpers.quote(query)) for url in urls]
        async for url, response in self.helpers.request_batch_stream(urls):
            keyserver = self.helpers.urlparse(url).netloc
            if response is not None:
                for email in await self.helpers.re.extract_emails(response.text):
                    email = email.lower()
                    if email.endswith(query):
                        results.add((email, keyserver))
        return results
