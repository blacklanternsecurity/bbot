from .crobat import crobat


class wayback(crobat):
    flags = ["passive", "subdomain-enum", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED", "DNS_NAME"]
    meta = {
        "description": "Query archive.org's API for subdomains",
    }
    options = {"urls": False, "garbage_threshold": 10}
    options_desc = {
        "urls": "emit URLs in addition to DNS_NAMEs",
        "garbage_threshold": "Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)",
    }
    in_scope_only = True

    base_url = "http://web.archive.org"

    def setup(self):
        self.urls = self.config.get("urls", False)
        self.garbage_threshold = self.config.get("garbage_threshold", 10)
        return super().setup()

    def handle_event(self, event):
        query = self.make_query(event)
        for result, event_type in self.query(query):
            self.emit_event(result, event_type, event, abort_if=self.abort_if)

    def query(self, query):
        waybackurl = f"{self.base_url}/cdx/search/cdx?url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        r = self.helpers.request(waybackurl, timeout=self.http_timeout + 10)
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

        dns_names = set()
        for parsed_url in self.helpers.collapse_urls(urls, threshold=self.garbage_threshold):
            if not self.urls:
                dns_name = parsed_url.hostname
                h = hash(dns_name)
                if h not in dns_names:
                    dns_names.add(h)
                    yield dns_name, "DNS_NAME"
            else:
                yield parsed_url.geturl(), "URL_UNVERIFIED"
