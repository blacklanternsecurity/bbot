import regex as re

from .emailformat import emailformat


class skymem(emailformat):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {
        "description": "Query skymem.info for email addresses",
        "created_date": "2022-07-11",
        "author": "@TheTechromancer",
    }

    base_url = "https://www.skymem.info"
    _qsize = 1

    async def setup(self):
        self.next_page_regex = self.helpers.re.compile(r'<a href="/domain/([a-z0-9]+)\?p=', re.I)
        return True

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        # get first page
        url = f"{self.base_url}/srch?q={self.helpers.quote(query)}"
        r = await self.api_request(url)
        if not r:
            return
        responses = [r]

        # iterate through other pages
        domain_ids = await self.helpers.re.findall(self.next_page_regex, r.text)
        if domain_ids:
            domain_id = domain_ids[0]
            for page in range(2, 22):
                r2 = await self.api_request(f"{self.base_url}/domain/{domain_id}?p={page}")
                if not r2:
                    continue
                responses.append(r2)
                pages = re.findall(r"/domain/" + domain_id + r"\?p=(\d+)", r2.text)
                if not pages:
                    break
                last_page = max([int(p) for p in pages])
                if page >= last_page:
                    break

        for i, r in enumerate(responses):
            for email in await self.helpers.re.extract_emails(r.text):
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    parent=event,
                    context=f'{{module}} searched skymem.info for "{query}" and found {{event.type}} on page {i + 1}: {{event.data}}',
                )
