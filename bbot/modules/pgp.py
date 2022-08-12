from bbot.modules.crobat import crobat


class pgp(crobat):
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

    def handle_event(self, event):
        query = self.make_query(event)
        results = self.query(query)
        if results:
            for hostname in results:
                if not hostname == event:
                    self.emit_event(hostname, "EMAIL_ADDRESS", event, abort_if=self.abort_if)

    def query(self, query):
        for url in self.config.get("search_urls", []):
            url = url.replace("<query>", self.helpers.quote(query))
            response = self.helpers.request(url)
            if response is not None:
                for email in self.helpers.extract_emails(response.text):
                    email = email.lower()
                    if email.lower().endswith(query):
                        yield email
