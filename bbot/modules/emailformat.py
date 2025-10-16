from bbot.modules.base import BaseModule


class emailformat(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {
        "description": "Query email-format.com for email addresses",
        "created_date": "2022-07-11",
        "author": "@TheTechromancer",
    }
    in_scope_only = False
    per_domain_only = True

    base_url = "https://www.email-format.com"

    async def setup(self):
        self.cfemail_regex = self.helpers.re.compile(r'data-cfemail="([0-9a-z]+)"')
        return True

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        url = f"{self.base_url}/d/{self.helpers.quote(query)}/"
        r = await self.api_request(url)
        if not r:
            return

        encrypted_emails = await self.helpers.re.findall(self.cfemail_regex, r.text)

        for enc in encrypted_emails:
            enc_len = len(enc)

            if enc_len < 2 or enc_len % 2 != 0:
                continue

            key = int(enc[:2], 16)

            email = "".join([chr(int(enc[i : i + 2], 16) ^ key) for i in range(2, enc_len, 2)]).lower()

            if email.endswith(query):
                await self.emit_event(
                    email,
                    "EMAIL_ADDRESS",
                    parent=event,
                    context=f'{{module}} searched email-format.com for "{query}" and found {{event.type}}: {{event.data}}',
                )
