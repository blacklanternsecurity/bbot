from bbot.modules.shodan_dns import shodan_dns


class censys(shodan_dns):
    """
    thanks to https://github.com/owasp-amass/amass/blob/master/resources/scripts/cert/censys.ads
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "EMAIL_ADDRESS", "IP_ADDRESS", "OPEN_PORT", "PROTOCOL"]
    flags = ["subdomain-enum", "email-enum", "passive", "safe"]
    meta = {"description": "Query the Censys API", "auth_required": True}
    options = {"api_id": "", "api_secret": ""}
    options_desc = {"api_id": "Censys.io API ID", "api_secret": "Censys.io API Secret"}

    base_url = "https://search.censys.io/api/v1"

    async def setup(self):
        self.api_id = self.config.get("api_id", "")
        self.api_secret = self.config.get("api_secret", "")
        self.auth = (self.api_id, self.api_secret)
        return await super().setup()

    async def ping(self):
        url = f"{self.base_url}/account"
        resp = await self.helpers.request(url, auth=self.auth)
        d = resp.json()
        assert isinstance(d, dict), f"Invalid response from {url}: {resp}"
        quota = d.get("quota", {})
        used = int(quota.get("used", 0))
        allowance = int(quota.get("allowance", 0))
        assert used < allowance, "No quota remaining"

    async def query(self, query):
        results = set()
        page = 1
        while 1:
            resp = await self.helpers.request(
                f"{self.base_url}/search/certificates",
                method="POST",
                json={
                    "query": f"parsed.names: {query}",
                    "page": page,
                    "fields": ["parsed.names"],
                },
                auth=self.auth,
            )
            page += 1

            if resp is None:
                break

            d = resp.json()
            if d is None:
                break
            elif not isinstance(d, dict):
                break

            error = d.get("error", "")
            if error:
                self.warning(error)

            if resp.status_code < 200 or resp.status_code >= 400:
                break

            elif d.get("status") is None or d["status"] != "ok" or len(d.get("results", [])) == 0:
                break

            for r in d["results"]:
                for v in r["parsed.names"]:
                    results.add(v.strip(".*").lower())

            metadata = d.get("metadata", {})
            if metadata.get("page", 0) >= metadata.get("pages", 0):
                break

        return results

    @property
    def auth_secret(self):
        return self.api_id and self.api_secret
