import re

from .emailformat import emailformat


class skymem(emailformat):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {"description": "Query skymem.info for email addresses"}

    base_url = "https://www.skymem.info"

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        # get first page
        url = f"{self.base_url}/srch?q={self.helpers.quote(query)}"
        r = await self.request_with_fail_count(url)
        if not r:
            return
        for email in self.helpers.extract_emails(r.text):
            self.emit_event(email, "EMAIL_ADDRESS", source=event)

        # iterate through other pages
        domain_ids = re.findall(r'<a href="/domain/([a-z0-9]+)\?p=', r.text, re.I)
        if not domain_ids:
            return
        domain_id = domain_ids[0]
        for page in range(2, 22):
            r2 = await self.request_with_fail_count(f"{self.base_url}/domain/{domain_id}?p={page}")
            if not r2:
                continue
            for email in self.helpers.extract_emails(r2.text):
                self.emit_event(email, "EMAIL_ADDRESS", source=event)
            pages = re.findall(r"/domain/" + domain_id + r"\?p=(\d+)", r2.text)
            if not pages:
                break
            last_page = max([int(p) for p in pages])
            if page >= last_page:
                break
