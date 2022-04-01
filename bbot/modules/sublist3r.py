from .base import BaseModule


class sublist3r(BaseModule):

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    target_only = True

    def handle_event(self, event):

        query = str(event.data).lower()

        results = self.helpers.request(f"https://api.sublist3r.com/search.php?domain={query}")

        try:
            json = results.json()
            if json:
                for hostname in json:
                    if hostname in self.scan.target and not hostname == event:
                        self.emit_event(hostname, "DNS_NAME", event)
                    else:
                        self.debug(f"Invalid subdomain: {hostname}")
        except Exception as e:
            self.error(f"Error retrieving sublist3r domains: {e}")
