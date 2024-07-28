from bbot.modules.templates.subdomain_enum import subdomain_enum


class rapiddns(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query rapiddns.io for subdomains",
        "created_date": "2022-08-24",
        "author": "@TheTechromancer",
    }

    base_url = "https://rapiddns.io"

    async def request_url(self, query):
        url = f"{self.base_url}/subdomain/{self.helpers.quote(query)}?full=1#result"
        response = await self.request_with_fail_count(url, timeout=self.http_timeout + 10)
        return response

    def parse_results(self, r, query):
        results = set()
        text = getattr(r, "text", "")
        for match in self.helpers.regexes.dns_name_regex.findall(text):
            match = match.lower()
            if match.endswith(query):
                results.add(match)
        return results
