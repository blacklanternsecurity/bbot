from bbot.modules.base import BaseModule


class emailformat(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {"description": "Query email-format.com for email addresses"}
    in_scope_only = False
    per_domain_only = True

    base_url = "https://www.email-format.com"

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        url = f"{self.base_url}/d/{self.helpers.quote(query)}/"
        r = await self.request_with_fail_count(url)
        if not r:
            return
        for email in self.helpers.extract_emails(r.text):
            if email.endswith(query):
                self.emit_event(email, "EMAIL_ADDRESS", source=event)
