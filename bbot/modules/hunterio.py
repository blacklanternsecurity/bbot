from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


class hunterio(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "DNS_NAME", "URL_UNVERIFIED"]
    flags = ["passive", "email-enum", "subdomain-enum", "safe"]
    meta = {
        "description": "Query hunter.io for emails",
        "created_date": "2022-04-25",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Hunter.IO API key"}

    base_url = "https://api.hunter.io/v2"
    limit = 100

    async def ping(self):
        url = f"{self.base_url}/account?api_key={self.api_key}"
        r = await self.helpers.request(url)
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    async def handle_event(self, event):
        query = self.make_query(event)
        for entry in await self.query(query):
            email = entry.get("value", "")
            sources = entry.get("sources", [])
            if email:
                email_event = self.make_event(email, "EMAIL_ADDRESS", event)
                if email_event:
                    await self.emit_event(
                        email_event,
                        context=f'{{module}} queried Hunter.IO API for "{query}" and found {{event.type}}: {{event.data}}',
                    )
                    for source in sources:
                        domain = source.get("domain", "")
                        if domain:
                            await self.emit_event(
                                domain,
                                "DNS_NAME",
                                email_event,
                                context=f"{{module}} originally found {email} at {{event.type}}: {{event.data}}",
                            )
                        url = source.get("uri", "")
                        if url:
                            await self.emit_event(
                                url,
                                "URL_UNVERIFIED",
                                email_event,
                                context=f"{{module}} originally found {email} at {{event.type}}: {{event.data}}",
                            )

    async def query(self, query):
        emails = []
        url = (
            f"{self.base_url}/domain-search?domain={query}&api_key={self.api_key}"
            + "&limit={page_size}&offset={offset}"
        )
        agen = self.helpers.api_page_iter(url, page_size=self.limit)
        try:
            async for j in agen:
                new_emails = j.get("data", {}).get("emails", [])
                if not new_emails:
                    break
                emails += new_emails
        finally:
            agen.aclose()
        return emails
