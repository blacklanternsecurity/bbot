from .crobat import crobat


class sitedossier(crobat):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {"description": "Query sitedossier.com for subdomains"}

    base_url = "http://www.sitedossier.com/parentdomain"
    max_pages = 10

    async def query(self, query, parse_fn=None, request_fn=None):
        results = set()
        base_url = f"{self.base_url}/{self.helpers.quote(query)}"
        url = str(base_url)
        for page in range(1, 100 * self.max_pages + 2, 100):
            if page > 1:
                url = f"{base_url}/{page}"
            response = await self.request(url)
            if response is None:
                self.info(f'Query "{query}" failed (no response)')
                return results
            if response.status_code == 302:
                self.verbose("Hit rate limit captcha")
                break
            for regex in self.scan.dns_regexes:
                for match in regex.finditer(response.text):
                    hostname = match.group().lower()
                    results.add(hostname)
            if '<a href="/parentdomain/' not in response.text:
                break

        return results
