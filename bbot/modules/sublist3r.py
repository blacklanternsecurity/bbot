from .crobat import crobat


class sublist3r(crobat):
    def query(self, query):
        results = self.helpers.request(f"https://api.sublist3r.com/search.php?domain={query}")
        try:
            json = results.json()
            if json:
                for hostname in json:
                    yield hostname
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            import traceback

            self.warning(f"Error retrieving sublist3r domains")
            self.debug(traceback.format_exc())
