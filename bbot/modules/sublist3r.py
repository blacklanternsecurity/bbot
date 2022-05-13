from .base import BaseModule


class sublist3r(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        if "target" in event.tags:
            return True
        elif hash(self.helpers.parent_domain(event.data)) not in self.processed:
            return True
        return False

    def handle_event(self, event):

        if not "target" in event.tags:
            query = self.helpers.parent_domain(event.data).lower()
        else:
            query = str(event.data).lower()

        if query not in self.processed:
            self.processed.add(hash(query))

            results = self.helpers.request(f"https://api.sublist3r.com/search.php?domain={query}")

            try:
                json = results.json()
                if json:
                    for hostname in json:
                        if not hostname == event:
                            self.emit_event(hostname, "DNS_NAME", event)
                        else:
                            self.debug(f"Invalid subdomain: {hostname}")
                else:
                    self.debug(f'No results for "{query}"')
            except Exception:
                import traceback

                self.warning(f"Error retrieving sublist3r domains")
                self.debug(traceback.format_exc())
