from .viewdns import viewdns


class emailformat(viewdns):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS"]
    flags = ["passive", "email-enum", "safe"]
    meta = {"description": "Query email-format.com for email addresses"}
    in_scope_only = False

    base_url = "https://www.email-format.com"

    def extract_emails(self, content):
        yield from self.helpers.regexes.email_regex.findall(content)

    def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        url = f"{self.base_url}/d/{self.helpers.quote(query)}/"
        r = self.request_with_fail_count(url)
        if not r:
            return
        for email in self.extract_emails(r.text):
            email = email.lower()
            if email.endswith(query):
                self.emit_event(email, "EMAIL_ADDRESS", source=event)
