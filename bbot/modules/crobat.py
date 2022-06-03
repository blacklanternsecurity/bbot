from .base import BaseModule


class crobat(BaseModule):

    flags = ["subdomain-enum"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    in_scope_only = True

    def setup(self):
        self.processed = set()
        return True

    def filter_event(self, event):
        if "target" in event.tags:
            return True
        # include out-of-scope DNS names that resolve to in-scope IPs
        elif event not in self.scan.target:
            if hash(self.helpers.parent_domain(event.data)) not in self.processed:
                return True
        return False

    def handle_event(self, event):
        if "target" in event.tags:
            query = str(event.data).lower()
        else:
            query = self.helpers.parent_domain(event.data).lower()

        if query not in self.processed:
            self.processed.add(hash(query))

            results = self.helpers.request(f"https://sonar.omnisint.io/subdomains/{query}")

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

                self.warning(f"Error retrieving crobat domains")
                self.debug(traceback.format_exc())
