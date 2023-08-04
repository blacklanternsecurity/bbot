from .crobat import crobat


class anubisdb(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query jldc.me's database for subdomains"}

    base_url = "https://jldc.me/anubis/subdomains"
    dns_abort_depth = 5

    async def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}"
        return await self.request_with_fail_count(url)

    def abort_if_pre(self, hostname):
        """
        Discards results that are longer than 5 segments, e.g. a.b.c.d.evilcorp.com
        This exists because of the _disgusting_ amount of garbage data in this API
        """
        dns_depth = hostname.count(".") + 1
        if dns_depth > self.dns_abort_depth:
            return True
        return False

    async def abort_if(self, event):
        # abort if dns name is unresolved
        if not "resolved" in event.tags:
            return True, "DNS name is unresolved"
        return await super().abort_if(event)

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json:
            for hostname in json:
                hostname = str(hostname).lower()
                if hostname.endswith(f".{query}") and not self.abort_if_pre(hostname):
                    results.add(hostname)
        return results
