import re

from bbot.modules.templates.subdomain_enum import subdomain_enum


class digitorus(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query certificatedetails.com for subdomains",
        "created_date": "2023-07-25",
        "author": "@TheTechromancer",
    }

    base_url = "https://certificatedetails.com"

    async def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}"
        return await self.helpers.request(url)

    def parse_results(self, r, query):
        results = set()
        content = getattr(r, "text", "")
        extract_regex = re.compile(r"[\w.-]+\." + query, re.I)
        if content:
            for match in extract_regex.finditer(content):
                subdomain = match.group().lower()
                if subdomain and subdomain.endswith(f".{query}"):
                    results.add(subdomain)
        return results
