from bbot.modules.crobat import crobat


class hackertarget(crobat):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {"description": "Query the hackertarget.com API for subdomains"}

    base_url = "https://api.hackertarget.com"

    async def request_url(self, query):
        url = f"{self.base_url}/hostsearch/?q={self.helpers.quote(query)}"
        response = await self.request_with_fail_count(url)
        return response

    def parse_results(self, r, query):
        for line in r.text.splitlines():
            host = line.split(",")[0]
            try:
                self.helpers.validators.validate_host(host)
                yield host
            except ValueError:
                self.set_error_state(host)
