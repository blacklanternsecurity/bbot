from .crobat import crobat


class wayback(crobat):
    flags = ["passive", "subdomain-enum"]
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED"]
    options = {"garbage_threshold": 5}
    options_desc = {
        "garbage_threshold": "Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)"
    }

    def setup(self):
        self.garbage_threshold = self.config.get("garbage_threshold", 5)
        return super().setup()

    def handle_event(self, event):
        query = self.make_query(event)
        for result in self.query(query):
            self.emit_event(result, "URL_UNVERIFIED", event, abort_if=self.abort_if)

    def query(self, query):
        waybackurl = f"http://web.archive.org/cdx/search/cdx?url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        r = self.helpers.request(waybackurl)
        if not r:
            self.warning(f'Error connecting to archive.org for query "{query}"')
            return
        try:
            j = r.json()
            assert type(j) == list
        except Exception:
            self.warning(f'Error JSON-decoding archive.org response for query "{query}"')
            return

        urls = []
        for result in j[1:]:
            try:
                url = result[0]
                urls.append(url)
            except KeyError:
                continue

        yield from self.helpers.collapse_urls(urls, threshold=self.garbage_threshold)
