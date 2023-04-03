import re
from bs4 import BeautifulSoup

from bbot.modules.base import BaseModule


class viewdns(BaseModule):
    """
    Used as a base for modules that only act on root domains and not individual hostnames
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "passive", "safe"]
    meta = {
        "description": "Query viewdns.info's reverse whois for related domains",
    }
    deps_pip = ["bs4", "lxml~=4.9.2"]
    base_url = "https://viewdns.info"
    in_scope_only = True
    _qsize = 1

    def setup(self):
        self.processed = set()
        self.date_regex = re.compile(r"\d{4}-\d{2}-\d{2}")
        return True

    def filter_event(self, event):
        _, domain = self.helpers.split_domain(event.data)
        if hash(domain) in self.processed:
            return False
        self.processed.add(hash(domain))
        return True

    def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        for domain, _ in self.query(query):
            self.emit_event(domain, "DNS_NAME", source=event, tags=["affiliate"])
            # todo: registrar?

    def query(self, query):
        url = f"{self.base_url}/reversewhois/?q={query}"
        r = self.helpers.request(url)
        status_code = getattr(r, "status_code", 0)
        if status_code not in (200,):
            self.verbose(f"Error retrieving reverse whois results (status code: {status_code})")

        content = getattr(r, "content", b"")
        html = BeautifulSoup(content, features="lxml")
        yielded = set()
        for table_row in html.findAll("tr"):
            table_cells = table_row.findAll("td")
            # make double-sure we're in the right table by checking the date field
            try:
                if self.date_regex.match(table_cells[1].text.strip()):
                    # domain == first cell
                    domain = table_cells[0].text.strip().lower()
                    # registrar == last cell
                    registrar = table_cells[-1].text.strip()
                    if domain and not domain == query:
                        to_yield = (domain, registrar)
                        to_yield_hash = hash(to_yield)
                        if to_yield_hash not in yielded:
                            yield to_yield
            except IndexError:
                self.debug(f"Invalid row {str(table_row)[:40]}...")
                continue
