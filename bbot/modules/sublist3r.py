from .base import BaseModule


class sublist3r(BaseModule):

    watched_events = ["HOSTNAME"]
    produced_events = ["HOSTNAME"]

    def handle_event(self, event):
        # only process targets
        if not "target" in event.tags:
            return

        query = str(event.data).lower()

        results = self.helpers.request(
            f"https://api.sublist3r.com/search.php?domain={query}"
        )

        try:
            json = results.json()
            if json:
                for hostname in json:
                    if hostname in self.scan.target and not hostname == event:
                        self.emit_event(hostname, "HOSTNAME", event)
                    else:
                        self.debug(f"Invalid subdomain: {hostname}")
        except Exception as e:
            self.error(f"Error retrieving sublist3r domains: {e}")
