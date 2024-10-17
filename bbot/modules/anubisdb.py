from bbot.modules.templates.subdomain_enum import subdomain_enum


class anubisdb(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query jldc.me's database for subdomains",
        "created_date": "2022-10-04",
        "author": "@TheTechromancer",
    }
    options = {"limit": 1000}
    options_desc = {
        "limit": "Limit the number of subdomains returned per query (increasing this may slow the scan due to garbage results from this API)"
    }

    base_url = "https://jldc.me/anubis/subdomains"
    dns_abort_depth = 5

    async def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}"
        return await self.api_request(url)

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
        if event.type == "DNS_NAME_UNRESOLVED":
            return True, "DNS name is unresolved"
        return await super().abort_if(event)

    def parse_results(self, r, query):
        results = set()
        json = r.json()
        if json:
            for hostname in json:
                hostname = str(hostname).lower()
                in_scope = hostname.endswith(f".{query}")
                is_ptr = self.helpers.is_ptr(hostname)
                too_long = self.abort_if_pre(hostname)
                if in_scope and not is_ptr and not too_long:
                    results.add(hostname)
        return sorted(results)[: self.config.get("limit", 1000)]
