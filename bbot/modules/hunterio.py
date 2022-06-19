from .base import BaseModule


class hunterio(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "DNS_NAME", "URL"]
    options = {"api_key": ""}
    options_desc = {"api_key": "Hunter.IO API key"}
    max_threads = 2
    in_scope_only = True

    def setup(self):
        self.limit = 100
        self.processed = set()
        self.emitted = set()
        self.api_key = self.config.get("api_key", "")
        if not self.api_key:
            self.warning("No API key specified")
            return False
        return True

    def filter_event(self, event):
        if "target" in event.tags:
            return True
        elif self.helpers.parent_domain(event.data) not in self.processed:
            return True
        return False

    def handle_event(self, event):
        if not "target" in event.tags:
            query = self.helpers.parent_domain(event.data).lower()
        else:
            query = str(event.data).lower()

        if query not in self.processed:
            self.processed.add(query)

        for entry in self.query(query):
            email = entry.get("value", "")
            sources = entry.get("sources", [])
            if email:
                email_event = self.scan.make_event(email, "EMAIL_ADDRESS", event)
                self.emit_event(email_event)
            for source in sources:
                domain = source.get("domain", "")
                if domain and not domain in self.emitted:
                    self.emitted.add(domain)
                    self.emit_event(domain, "DNS_NAME", email_event)
                url = source.get("uri", "")
                if url and not url in self.emitted:
                    self.emitted.add(url)
                    self.emit_event(url, "URL", email_event)

    def query(self, query):
        emails = []
        offset = 0
        while 1:
            url = f"https://api.hunter.io/v2/domain-search?domain={query}&api_key={self.api_key}&limit={self.limit}&offset={offset}"
            results = self.helpers.request(url)

            try:
                json = results.json()
                if not json:
                    self.warning("Empty response")
                    break
                new_emails = json.get("data", {}).get("emails", [])
                if not new_emails:
                    break
                offset += self.limit
                emails += new_emails
            except Exception:
                import traceback

                self.warning(f"Error retrieving emails")
                self.debug(traceback.format_exc())
                break
        return emails
