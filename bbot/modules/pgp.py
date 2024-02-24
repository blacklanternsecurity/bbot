from bbot.modules.templates.subdomain_enum import subdomain_enum


class pgp(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {"description": "Query common PGP servers for email addresses"}
    options = {
        "search_urls": [
            "https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=vindex&search=<query>",
            "http://the.earth.li:11371/pks/lookup?fingerprint=on&op=vindex&search=<query>",
        ]
    }
    options_desc = {"search_urls": "PGP key servers to search"}

    async def handle_event(self, event):
        query = self.make_query(event)
        results = await self.query(query)
        if results:
            for hostname in results:
                if not hostname == event:
                    await self.emit_event(hostname, "EMAIL_ADDRESS", event, abort_if=self.abort_if)

    async def query(self, query):
        results = set()
        for url in self.config.get("search_urls", []):
            url = url.replace("<query>", self.helpers.quote(query))
            response = await self.helpers.request(url)
            if response is not None:
                for email in self.helpers.extract_emails(response.text):
                    email = email.lower()
                    if email.endswith(query):
                        results.add(email)
        return results
