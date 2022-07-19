from .crobat import crobat


class sublist3r(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]

    base_url = "https://api.sublist3r.com/search.php"

    def query(self, query):
        results = self.helpers.request(f"{self.base_url}?domain={query}")
        try:
            json = results.json()
            if json:
                for hostname in json:
                    yield hostname
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving sublist3r domains for {query}")
            self.debug(traceback.format_exc())
