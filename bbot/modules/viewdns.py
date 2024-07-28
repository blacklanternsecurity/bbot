import re

from bbot.modules.base import BaseModule


class viewdns(BaseModule):
    """
    Todo: Also retrieve registrar?
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "passive", "safe"]
    meta = {
        "description": "Query viewdns.info's reverse whois for related domains",
        "created_date": "2022-07-04",
        "author": "@TheTechromancer",
    }
    base_url = "https://viewdns.info"
    in_scope_only = True
    per_domain_only = True
    _qsize = 1

    async def setup(self):
        self.date_regex = re.compile(r"\d{4}-\d{2}-\d{2}")
        return True

    async def handle_event(self, event):
        _, query = self.helpers.split_domain(event.data)
        for domain, _ in await self.query(query):
            await self.emit_event(
                domain,
                "DNS_NAME",
                parent=event,
                tags=["affiliate"],
                context=f'{{module}} searched viewdns.info for "{query}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, query):
        results = set()
        url = f"{self.base_url}/reversewhois/?q={query}"
        r = await self.helpers.request(url)
        status_code = getattr(r, "status_code", 0)
        if status_code not in (200,):
            self.verbose(f"Error retrieving reverse whois results (status code: {status_code})")

        content = getattr(r, "content", b"")

        html = self.helpers.beautifulsoup(content, "html.parser")
        if html is False:
            self.debug(f"BeautifulSoup returned False")
            return results
        found = set()
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
                        result = (domain, registrar)
                        result_hash = hash(result)
                        if result_hash not in found:
                            found.add(result_hash)
                            results.add(result)
            except IndexError:
                self.debug(f"Invalid row {str(table_row)[:40]}...")
                continue
        return results
