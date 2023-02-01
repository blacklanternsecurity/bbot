from .shodan_dns import shodan_dns


class hunterio(shodan_dns):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "DNS_NAME", "URL_UNVERIFIED"]
    flags = ["passive", "email-enum", "subdomain-enum", "safe"]
    meta = {"description": "Query hunter.io for emails", "auth_required": True}
    options = {"api_key": ""}
    options_desc = {"api_key": "Hunter.IO API key"}

    base_url = "https://api.hunter.io/v2"

    def setup(self):
        self.limit = 100
        return super().setup()

    def ping(self):
        r = self.helpers.request(f"{self.base_url}/account?api_key={self.api_key}")
        resp_content = getattr(r, "text", "")
        assert getattr(r, "status_code", 0) == 200, resp_content

    def handle_event(self, event):
        query = self.make_query(event)
        for entry in self.query(query):
            email = entry.get("value", "")
            sources = entry.get("sources", [])
            if email:
                email_event = self.make_event(email, "EMAIL_ADDRESS", event)
                if email_event:
                    self.emit_event(email_event)
                    for source in sources:
                        domain = source.get("domain", "")
                        if domain:
                            self.emit_event(domain, "DNS_NAME", email_event)
                        url = source.get("uri", "")
                        if url:
                            self.emit_event(url, "URL_UNVERIFIED", email_event)

    def query(self, query):
        emails = []
        url = (
            f"{self.base_url}/domain-search?domain={query}&api_key={self.api_key}"
            + "&limit={page_size}&offset={offset}"
        )
        for j in self.helpers.api_page_iter(url, page_size=self.limit):
            new_emails = j.get("data", {}).get("emails", [])
            if not new_emails:
                break
            emails += new_emails
        return emails
