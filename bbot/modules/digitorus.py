from .crobat import crobat


class digitorus(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query certificatedetails.com for subdomains"}

    base_url = "https://certificatedetails.com"

    async def request_url(self, query):
        url = f"{self.base_url}/{self.helpers.quote(query)}"
        return await self.helpers.request(url)

    def parse_results(self, r, query):
        results = set()
        content = getattr(r, "text", "")
        if content:
            for regex in self.scan.dns_regexes:
                for match in regex.finditer(content):
                    subdomain = match.group().lower()
                    if subdomain:
                        results.add(subdomain)
        return results
