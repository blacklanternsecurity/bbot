from .base import BaseModule


class azure_realm(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED"]
    flags = ["affiliates", "subdomain-enum", "cloud-enum", "web-basic", "passive", "safe"]
    meta = {
        "description": 'Retrieves the "AuthURL" from login.microsoftonline.com/getuserrealm',
        "created_date": "2023-07-12",
        "author": "@TheTechromancer",
    }

    async def setup(self):
        self.processed = set()
        return True

    async def handle_event(self, event):
        _, domain = self.helpers.split_domain(event.data)
        domain_hash = hash(domain)
        if domain_hash not in self.processed:
            self.processed.add(domain_hash)
            auth_url = await self.getuserrealm(domain)
            if auth_url:
                url_event = self.make_event(
                    auth_url, "URL_UNVERIFIED", parent=event, tags=["affiliate", "ms-auth-url"]
                )
                url_event.source_domain = domain
                await self.emit_event(
                    url_event,
                    context="{module} queried login.microsoftonline.com for user realm and found {event.type}: {event.data}",
                )

    async def getuserrealm(self, domain):
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login=test@{domain}"
        r = await self.helpers.request(url)
        if r is None:
            return
        try:
            json = r.json()
        except Exception:
            return
        if json and isinstance(json, dict):
            return json.get("AuthURL", "")
